/*
 * Browser implementation of the Ninja Kiwi save container used by Bloons
 * Blitz. The format and password/app ID follow the reference project:
 * https://github.com/MrNukeAlt/Bloons-Blitz-Save-Editor
 */

(() => {
  "use strict";

  const PASSWORD = "26";
  const PREFIX_LENGTH = 8;
  const BASE_HEADER_LENGTH = 36;
  const PASSWORD_INDEX_LENGTH = 8;
  const SALT_LENGTH = 24;
  const AES_BLOCK_LENGTH = 16;
  const PBKDF2_ITERATIONS = 10;
  const DOTNET_UNIX_EPOCH_UTC = 5233041986427387904n;
  const DOTNET_TICKS_PER_MS = 10000n;

  const state = {
    fileName: "",
    originalBytes: null,
    originalPlaintext: null,
    container: null,
    object: null,
    rawText: "",
    isJson: false,
    keepBom: false,
    mode: "normal",
    dirty: false,
  };

  const dom = {
    welcomeView: document.querySelector("#welcomeView"),
    editorView: document.querySelector("#editorView"),
    fileInput: document.querySelector("#fileInput"),
    openButton: document.querySelector("#openButton"),
    verifyButton: document.querySelector("#verifyButton"),
    resetButton: document.querySelector("#resetButton"),
    downloadButton: document.querySelector("#downloadButton"),
    clearButton: document.querySelector("#clearButton"),
    selectAllButton: document.querySelector("#selectAllButton"),
    fileName: document.querySelector("#fileName"),
    fileType: document.querySelector("#fileType"),
    payloadStat: document.querySelector("#payloadStat"),
    payloadDetail: document.querySelector("#payloadDetail"),
    saveCountStat: document.querySelector("#saveCountStat"),
    containerStat: document.querySelector("#containerStat"),
    containerDetail: document.querySelector("#containerDetail"),
    dirtyStat: document.querySelector("#dirtyStat"),
    dirtyDetail: document.querySelector("#dirtyDetail"),
    payloadKind: document.querySelector("#payloadKind"),
    editorHeading: document.querySelector("#editorHeading"),
    normalEditor: document.querySelector("#normalEditor"),
    rawEditorPanel: document.querySelector("#rawEditorPanel"),
    rawEditor: document.querySelector("#rawEditor"),
    rawValidation: document.querySelector("#rawValidation"),
    characterCount: document.querySelector("#characterCount"),
    metadataText: document.querySelector("#metadataText"),
    statusBar: document.querySelector("#statusBar"),
    statusText: document.querySelector("#statusText"),
    toast: document.querySelector("#toast"),
    modeButtons: [...document.querySelectorAll("[data-mode]")],
  };

  function makeElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  function clearElement(element) {
    while (element.firstChild) element.removeChild(element.firstChild);
  }

  function setStatus(message, tone = "neutral") {
    dom.statusText.textContent = message;
    dom.statusBar.dataset.tone = tone;
  }

  let toastTimer = null;
  function showToast(message, tone = "neutral") {
    dom.toast.textContent = message;
    dom.toast.dataset.tone = tone;
    dom.toast.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => { dom.toast.hidden = true; }, 4200);
  }

  function formatBytes(value) {
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / (1024 * 1024)).toFixed(2)} MB`;
  }

  function formatCount(value) {
    return Number(value).toLocaleString("en-US");
  }

  function readU32(bytes, offset) {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, true);
  }

  function writeU32(bytes, offset, value) {
    new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).setUint32(offset, value, true);
  }

  function readU64(bytes, offset) {
    let value = 0n;
    for (let index = 7; index >= 0; index -= 1) {
      value = (value << 8n) | BigInt(bytes[offset + index]);
    }
    return value;
  }

  function writeU64(bytes, offset, value) {
    let current = BigInt(value);
    for (let index = 0; index < 8; index += 1) {
      bytes[offset + index] = Number(current & 255n);
      current >>= 8n;
    }
  }

  function bytesToWordArray(bytes) {
    const words = [];
    for (let index = 0; index < bytes.length; index += 1) {
      words[index >>> 2] = (words[index >>> 2] || 0) | (bytes[index] << (24 - (index % 4) * 8));
    }
    return CryptoJS.lib.WordArray.create(words, bytes.length);
  }

  function wordArrayToBytes(wordArray) {
    const length = wordArray.sigBytes;
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index += 1) {
      bytes[index] = (wordArray.words[index >>> 2] >>> (24 - (index % 4) * 8)) & 255;
    }
    return bytes;
  }

  function concatBytes(...parts) {
    const length = parts.reduce((total, part) => total + part.length, 0);
    const output = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  }

  function deriveKeyAndIv(password, salt) {
    const derived = CryptoJS.PBKDF2(
      CryptoJS.enc.Utf8.parse(password),
      bytesToWordArray(salt),
      { keySize: 8, iterations: PBKDF2_ITERATIONS, hasher: CryptoJS.algo.SHA1 },
    );
    return {
      iv: CryptoJS.lib.WordArray.create(derived.words.slice(0, 4), 16),
      key: CryptoJS.lib.WordArray.create(derived.words.slice(4, 8), 16),
    };
  }

  function pkcs7Pad(bytes) {
    const amount = AES_BLOCK_LENGTH - (bytes.length % AES_BLOCK_LENGTH || 0);
    const output = new Uint8Array(bytes.length + amount);
    output.set(bytes);
    output.fill(amount, bytes.length);
    return output;
  }

  function pkcs7Unpad(bytes) {
    if (!bytes.length || bytes.length % AES_BLOCK_LENGTH) {
      throw new Error("Invalid padded AES data length.");
    }
    const amount = bytes[bytes.length - 1];
    if (amount < 1 || amount > AES_BLOCK_LENGTH) {
      throw new Error("Invalid PKCS#7 padding.");
    }
    for (let index = bytes.length - amount; index < bytes.length; index += 1) {
      if (bytes[index] !== amount) throw new Error("Invalid PKCS#7 padding.");
    }
    return bytes.slice(0, bytes.length - amount);
  }

  function aesDecrypt(ciphertext, key, iv) {
    const params = CryptoJS.lib.CipherParams.create({ ciphertext: bytesToWordArray(ciphertext) });
    const plain = CryptoJS.AES.decrypt(params, key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.NoPadding,
    });
    return wordArrayToBytes(plain);
  }

  function aesEncrypt(plaintext, key, iv) {
    const encrypted = CryptoJS.AES.encrypt(bytesToWordArray(plaintext), key, {
      iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.NoPadding,
    });
    return wordArrayToBytes(encrypted.ciphertext);
  }

  function parseContainer(bytes) {
    if (bytes.length < PREFIX_LENGTH) throw new Error("File is too short to contain a save header.");
    const version = readU32(bytes, 0);
    const headerLength = readU32(bytes, 4);
    if (headerLength < BASE_HEADER_LENGTH || headerLength > 1024 * 1024) {
      throw new Error(`Not a compatible Ninja Kiwi container (version=${version}, header_length=${headerLength}).`);
    }
    const headerEnd = PREFIX_LENGTH + headerLength;
    const metadataEnd = headerEnd + PASSWORD_INDEX_LENGTH + SALT_LENGTH;
    if (bytes.length < metadataEnd) throw new Error("File is truncated before the encryption metadata.");
    const ciphertext = bytes.slice(metadataEnd);
    if (!ciphertext.length) throw new Error("Save contains no encrypted payload.");
    if (ciphertext.length % AES_BLOCK_LENGTH) throw new Error("Encrypted payload is not a multiple of 16 bytes.");
    return {
      version,
      headerLength,
      saveCount: readU32(bytes, 8),
      guid: bytes.slice(12, 28),
      unknown: bytes.slice(28, 36),
      timestamp: readU64(bytes, 36),
      extension: bytes.slice(44, headerEnd),
      passwordIndex: readU64(bytes, headerEnd),
      salt: bytes.slice(headerEnd + PASSWORD_INDEX_LENGTH, metadataEnd),
      ciphertext,
    };
  }

  function serializeContainer(container, ciphertext, saveCount, timestamp, salt) {
    const headerLength = BASE_HEADER_LENGTH + container.extension.length;
    if (salt.length !== SALT_LENGTH) throw new Error("Salt must be exactly 24 bytes.");
    const output = new Uint8Array(PREFIX_LENGTH + headerLength + PASSWORD_INDEX_LENGTH + SALT_LENGTH + ciphertext.length);
    writeU32(output, 0, container.version);
    writeU32(output, 4, headerLength);
    writeU32(output, 8, saveCount);
    output.set(container.guid, 12);
    output.set(container.unknown, 28);
    writeU64(output, 36, timestamp);
    output.set(container.extension, 44);
    writeU64(output, 8 + headerLength, container.passwordIndex);
    output.set(salt, 8 + headerLength + PASSWORD_INDEX_LENGTH);
    output.set(ciphertext, 8 + headerLength + PASSWORD_INDEX_LENGTH + SALT_LENGTH);
    return output;
  }

  function decryptSave(bytes, password = PASSWORD) {
    const container = parseContainer(bytes);
    const { key, iv } = deriveKeyAndIv(password, container.salt);
    const compressed = pkcs7Unpad(aesDecrypt(container.ciphertext, key, iv));
    let plaintext;
    try {
      plaintext = new Uint8Array(pako.inflate(compressed));
    } catch (error) {
      throw new Error("zlib decompression failed. The password may be incorrect or this is not a compatible save.");
    }
    return { container, plaintext };
  }

  function encryptSave(plaintext, template, password = PASSWORD) {
    if (template.saveCount >= 0xffffffff) throw new Error("Save count is already at its maximum value.");
    const compressed = new Uint8Array(pako.deflate(plaintext, { level: 3 }));
    const padded = pkcs7Pad(compressed);
    const salt = new Uint8Array(SALT_LENGTH);
    crypto.getRandomValues(salt);
    const { key, iv } = deriveKeyAndIv(password, salt);
    const ciphertext = aesEncrypt(padded, key, iv);
    const timestamp = DOTNET_UNIX_EPOCH_UTC + BigInt(Date.now()) * DOTNET_TICKS_PER_MS;
    return serializeContainer(template, ciphertext, template.saveCount + 1, timestamp, salt);
  }

  function hasBom(bytes) {
    return bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf;
  }

  function decodePayload(bytes) {
    const keepBom = hasBom(bytes);
    const data = keepBom ? bytes.slice(3) : bytes;
    const text = new TextDecoder("utf-8").decode(data);
    let object = null;
    let isJson = false;
    try {
      object = JSON.parse(text);
      isJson = true;
    } catch (_) {
      // Plain UTF-8 payloads are supported by the reference editor too.
    }
    return { text, object, isJson, keepBom };
  }

  function encodeText(text, keepBom) {
    const bytes = new TextEncoder().encode(text);
    return keepBom ? concatBytes(new Uint8Array([0xef, 0xbb, 0xbf]), bytes) : bytes;
  }

  function getPath(object, path, fallback) {
    let current = object;
    for (const key of path) {
      if (current === null || current === undefined || !(key in Object(current))) return fallback;
      current = current[key];
    }
    return current === undefined ? fallback : current;
  }

  function setPath(object, path, value) {
    let current = object;
    for (let index = 0; index < path.length - 1; index += 1) {
      const key = path[index];
      if (!current[key] || typeof current[key] !== "object") current[key] = {};
      current = current[key];
    }
    current[path[path.length - 1]] = value;
  }

  function inferKind(value, fallback) {
    if (fallback) return fallback;
    if (typeof value === "boolean") return "boolean";
    if (typeof value === "number") return "number";
    if (Array.isArray(value)) return "list";
    return "text";
  }

  function scalarEntries(object) {
    if (!object || typeof object !== "object" || Array.isArray(object)) return [];
    return Object.entries(object).filter(([, value]) => value === null || ["string", "number", "boolean"].includes(typeof value));
  }

  function itemIdentifier(item, index) {
    if (!item || typeof item !== "object") return `Item ${index + 1}`;
    return String(item.id ?? item.Id ?? item.key ?? item.name ?? `Item ${index + 1}`);
  }

  function fieldDescriptor(path, label, fallback, kind) {
    return { path, label, fallback, kind };
  }

  function addSection(parent, title, description, options = {}) {
    const section = makeElement("section", `form-section${options.wide ? " section-wide" : ""}`);
    const heading = makeElement("div", "section-heading");
    heading.append(makeElement("h3", "", title));
    if (description) heading.append(makeElement("p", "", description));
    const body = makeElement("div", "section-body");
    section.append(heading, body);
    parent.append(section);
    return body;
  }

  function addField(parent, descriptor) {
    const row = makeElement("label", "field-row");
    const label = makeElement("span", "field-label");
    label.append(makeElement("strong", "", descriptor.label));
    label.append(makeElement("span", "field-key", descriptor.path.join(".")));
    const value = getPath(state.object, descriptor.path, descriptor.fallback);
    const kind = inferKind(value, descriptor.kind);
    let input;
    if (kind === "boolean") {
      input = document.createElement("input");
      input.type = "checkbox";
      input.className = "boolean-input";
      input.checked = Boolean(value);
    } else {
      input = document.createElement(kind === "number" ? "input" : "input");
      input.type = kind === "number" ? "number" : "text";
      input.className = "field-input";
      if (kind === "number") input.step = Number.isInteger(Number(value)) ? "1" : "any";
      if (kind === "list") input.value = Array.isArray(value) ? value.join(", ") : "";
      else input.value = value === null || value === undefined ? "" : String(value);
    }
    input.dataset.path = JSON.stringify(descriptor.path);
    input.dataset.kind = kind;
    input.addEventListener("change", () => {
      let next;
      if (kind === "boolean") next = input.checked;
      else if (kind === "number") {
        next = Number(input.value);
        if (!Number.isFinite(next)) {
          showToast(`${descriptor.label} must be a valid number.`, "error");
          input.value = String(value ?? "");
          return;
        }
      } else if (kind === "list") {
        next = input.value.split(",").map((item) => item.trim()).filter(Boolean);
      } else next = input.value;
      setPath(state.object, descriptor.path, next);
      markDirty();
    });
    row.append(label, input);
    parent.append(row);
  }

  function addFields(parent, descriptors) {
    descriptors.forEach((descriptor) => addField(parent, descriptor));
  }

  function addObjectFields(parent, objectPath, object, labelPrefix = "") {
    const entries = scalarEntries(object);
    if (!entries.length) {
      parent.append(makeElement("div", "empty-hint", "No scalar fields in this object."));
      return;
    }
    entries.forEach(([key, value]) => {
      if (key === "id" || key === "Id" || key === "key" || key === "name") return;
      addField(parent, fieldDescriptor([...objectPath, key], `${labelPrefix}${key}`, value, inferKind(value)));
    });
  }

  function addCollection(parent, title, path, options = {}) {
    const collection = makeElement("div", "collection");
    collection.append(makeElement("div", "collection-title collection-label", title));
    const items = getPath(state.object, path, []);
    if (!Array.isArray(items) || !items.length) {
      collection.append(makeElement("div", "empty-hint", "No items in this save."));
      parent.append(collection);
      return;
    }
    items.forEach((item, index) => {
      const block = makeElement("div", "collection-block");
      const heading = makeElement("div", "collection-title");
      heading.append(makeElement("span", "", itemIdentifier(item, index)));
      heading.append(makeElement("span", "", `#${index + 1}`));
      block.append(heading);
      if (options.fields) {
        const descriptors = options.fields.map((field) => fieldDescriptor([...path, index, field.path], field.label, field.fallback, field.kind));
        addFields(block, descriptors);
      } else {
        addObjectFields(block, [...path, index], item);
      }
      collection.append(block);
    });
    parent.append(collection);
  }

  function renderNormalEditor() {
    clearElement(dom.normalEditor);
    if (!state.isJson || !state.object) {
      const body = addSection(dom.normalEditor, "Prepared fields unavailable", "This payload is plain text. Use Raw edit to work with it.", { wide: true });
      body.append(makeElement("div", "empty-hint", "The prepared editor requires a JSON payload."));
      return;
    }

    const general = addSection(dom.normalEditor, "General & currencies", "Player state and balances.");
    addFields(general, [
      fieldDescriptor(["playerLevel"], "Player level", 1, "number"),
      fieldDescriptor(["playerLevelProgress"], "Level progress", 0, "number"),
      fieldDescriptor(["playerPowerLevel"], "Player power level", 1, "number"),
      fieldDescriptor(["currentHeroId"], "Current hero ID", "", "text"),
      fieldDescriptor(["selectedLanguage"], "Language", "English", "text"),
      fieldDescriptor(["completedFirstLevel"], "Completed first level", false, "boolean"),
      fieldDescriptor(["acceptedTermsOfService"], "Accepted terms", false, "boolean"),
    ]);
    const currencies = getPath(state.object, ["currencies"], {});
    Object.entries(currencies && typeof currencies === "object" ? currencies : {}).forEach(([key, value]) => {
      addField(general, fieldDescriptor(["currencies", key], key, value, "number"));
    });

    const metadata = addSection(dom.normalEditor, "Metadata & info", "Versions, timestamps, and identifiers.");
    addFields(metadata, [
      fieldDescriptor(["createdAtDataVersion"], "Created data version", 0, "number"),
      fieldDescriptor(["createdAtGameVersion"], "Created game version", "", "text"),
      fieldDescriptor(["createdAt"], "Created timestamp", "", "text"),
      fieldDescriptor(["lastSavedAtDataVersion"], "Last saved data version", 0, "number"),
      fieldDescriptor(["lastSavedAtGameVersion"], "Last saved game version", "", "text"),
      fieldDescriptor(["lastSavedAt"], "Last saved timestamp", "", "text"),
      fieldDescriptor(["birthday_ts"], "Birthday timestamp", "", "text"),
      fieldDescriptor(["saveGameGuid"], "Save game GUID", "", "text"),
      fieldDescriptor(["encountersWalletId"], "Encounters wallet ID", "", "text"),
      fieldDescriptor(["encountersChecksum"], "Encounters checksum", "", "text"),
    ]);

    const monkeys = addSection(dom.normalEditor, "Monkeys", "Monkey levels and XP.", { wide: true });
    addCollection(monkeys, "Monkeys", ["monkeys"], { fields: [
      { path: ["level"], label: "Level", fallback: 1, kind: "number" },
      { path: ["currentXP"], label: "Current XP", fallback: 0, kind: "number" },
    ] });

    const heroes = addSection(dom.normalEditor, "Heroes & gear", "Hero progression and owned gear.", { wide: true });
    addCollection(heroes, "Heroes", ["heroes"], { fields: [
      { path: ["level"], label: "Level", fallback: 1, kind: "number" },
      { path: ["heroPowerLevel"], label: "Power level", fallback: 0, kind: "number" },
      { path: ["currentXP"], label: "Current XP", fallback: 0, kind: "number" },
    ] });
    addCollection(heroes, "Owned gear", ["ownedGear"]);

    const inventory = addSection(dom.normalEditor, "Inventory", "Consumables, toys, and spent toys.", { wide: true });
    addCollection(inventory, "Consumables", ["consumables"]);
    addCollection(inventory, "Toys", ["toys"]);
    addCollection(inventory, "Spent toys", ["spentToys"]);

    const missions = addSection(dom.normalEditor, "Missions & FTUE", "Daily missions and first-time user progress.", { wide: true });
    addCollection(missions, "Daily missions", ["profileDailyMissions", "currentMissions"], { fields: [
      { path: ["count"], label: "Count", fallback: 0, kind: "number" },
    ] });
    const ftue = getPath(state.object, ["ftueProgress"], {});
    const ftueBody = makeElement("div", "collection-block");
    ftueBody.append(makeElement("div", "collection-title", "FTUE progress"));
    addObjectFields(ftueBody, ["ftueProgress"], ftue);
    missions.append(ftueBody);

    const map = addSection(dom.normalEditor, "Map & progress", "Unlock and selection state.");
    const lastUnlocked = getPath(state.object, ["lastUnlockedLevel"], {});
    const selectedMap = getPath(state.object, ["selectedMapLevel"], {});
    const lastBlock = makeElement("div", "collection-block");
    lastBlock.append(makeElement("div", "collection-title", "Last unlocked level"));
    addObjectFields(lastBlock, ["lastUnlockedLevel"], lastUnlocked);
    map.append(lastBlock);
    const selectedBlock = makeElement("div", "collection-block");
    selectedBlock.append(makeElement("div", "collection-title", "Selected map level"));
    addObjectFields(selectedBlock, ["selectedMapLevel"], selectedMap);
    map.append(selectedBlock);

    const upgrades = addSection(dom.normalEditor, "Upgrades & stickers", "Lists are comma-separated.");
    addField(upgrades, fieldDescriptor(["upgradesChosenEver"], "Upgrades chosen ever", [], "list"));
    addField(upgrades, fieldDescriptor(["chosenUpgradesPendingFirstTimeBonus"], "Pending first-time bonus", [], "list"));
    addField(upgrades, fieldDescriptor(["stickersUsedEver"], "Stickers used ever", [], "list"));

    const loot = addSection(dom.normalEditor, "Loot & rewards", "Loot boxes and reward tracking.", { wide: true });
    addCollection(loot, "Loot boxes", ["lootBoxes"]);
    addCollection(loot, "Loot box keys", ["lootBoxKeys"]);
    addCollection(loot, "Reward tracking", ["rewardTrackingData"], { fields: [
      { path: ["opened"], label: "Opened", fallback: 0, kind: "number" },
    ] });

    const misc = addSection(dom.normalEditor, "Trading, stats & misc", "Run counters and trading state.", { wide: true });
    addFields(misc, [
      fieldDescriptor(["runCount"], "Run count", 0, "number"),
      fieldDescriptor(["numLevelsCompleted"], "Levels completed", 0, "number"),
      fieldDescriptor(["numGamesQuit"], "Games quit", 0, "number"),
      fieldDescriptor(["lastToyTradingResetTime"], "Toy trading reset", "", "text"),
    ]);
    addCollection(misc, "Hero trading toys", ["heroTradingToys"], { fields: [
      { path: ["offeringToyId"], label: "Offering toy", fallback: "", kind: "text" },
      { path: ["tradingToyId"], label: "Target toy", fallback: "", kind: "text" },
    ] });
    const ads = getPath(state.object, ["adWatchTracking"], {});
    const adBlock = makeElement("div", "collection-block");
    adBlock.append(makeElement("div", "collection-title", "Ad watch tracking"));
    Object.entries(ads && typeof ads === "object" ? ads : {}).forEach(([key, value]) => {
      addField(adBlock, fieldDescriptor(["adWatchTracking", key, "numberOfWatchesThisPeriod"], key, value?.numberOfWatchesThisPeriod ?? 0, "number"));
    });
    misc.append(adBlock);
  }

  function markDirty() {
    state.dirty = true;
    updateDirtyUI();
    updateCharacterCount();
  }

  function updateCharacterCount() {
    let text = state.rawText;
    if (state.isJson && state.mode === "normal" && state.object) text = JSON.stringify(state.object, null, 2);
    dom.characterCount.textContent = `${formatCount(text.length)} characters`;
  }

  function updateDirtyUI() {
    dom.dirtyStat.textContent = state.dirty ? "Edited" : "Ready";
    dom.dirtyDetail.textContent = state.dirty ? "Export a new verified save" : "No edits yet";
    const statusCard = dom.dirtyStat.closest(".status-card");
    if (statusCard) statusCard.dataset.dirty = String(state.dirty);
  }

  function setRawValidation(message, tone = "neutral") {
    dom.rawValidation.textContent = message;
    dom.rawValidation.dataset.tone = tone;
  }

  function syncRawFromObject() {
    if (state.isJson && state.object) {
      state.rawText = JSON.stringify(state.object, null, 2);
      dom.rawEditor.value = state.rawText;
    }
    updateCharacterCount();
  }

  function switchMode(mode) {
    if (mode === "normal" && !state.isJson) {
      showToast("Prepared fields require a JSON payload. Use Raw edit for this file.", "error");
      return;
    }
    if (mode === "raw") {
      if (state.mode === "normal") syncRawFromObject();
      dom.rawEditor.value = state.rawText;
      setRawValidation("Raw text is editable. JSON is checked on export.");
    } else {
      if (state.isJson && state.mode === "raw") {
        try {
          state.object = JSON.parse(dom.rawEditor.value);
          state.rawText = dom.rawEditor.value;
          renderNormalEditor();
        } catch (error) {
          setRawValidation(`Invalid JSON: ${error.message}`, "error");
          showToast("Fix the JSON error before leaving Raw edit.", "error");
          return;
        }
      }
    }
    state.mode = mode;
    dom.normalEditor.hidden = mode !== "normal";
    dom.rawEditorPanel.hidden = mode !== "raw";
    dom.editorHeading.textContent = mode === "normal" ? "Prepared fields" : "Raw edit";
    dom.modeButtons.forEach((button) => {
      const active = button.dataset.mode === mode;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", String(active));
    });
    updateCharacterCount();
  }

  function updateLoadedUI() {
    const { container } = state;
    dom.fileName.textContent = state.fileName;
    dom.fileType.textContent = `${state.isJson ? "JSON payload" : "UTF-8 text payload"} · ${formatBytes(state.originalBytes.length)}`;
    dom.payloadStat.textContent = state.isJson ? "JSON" : "Text";
    dom.payloadDetail.textContent = `${formatBytes(state.originalPlaintext.length)} decrypted`;
    dom.saveCountStat.textContent = formatCount(container.saveCount);
    dom.containerStat.textContent = `v${container.version}`;
    dom.containerDetail.textContent = `header ${container.headerLength} bytes`;
    dom.payloadKind.textContent = state.isJson ? "JSON" : "TEXT";
    dom.metadataText.textContent = metadataSummary(container, state.originalPlaintext);
    dom.editorView.hidden = false;
    dom.welcomeView.hidden = true;
    dom.verifyButton.disabled = false;
    dom.resetButton.disabled = false;
    dom.downloadButton.disabled = false;
    dom.clearButton.disabled = false;
    dom.modeButtons.find((button) => button.dataset.mode === "normal").setAttribute("aria-disabled", String(!state.isJson));
    renderNormalEditor();
    dom.rawEditor.value = state.rawText;
    state.mode = state.isJson ? "normal" : "raw";
    switchMode(state.mode);
    updateDirtyUI();
    updateCharacterCount();
  }

  function metadataSummary(container, plaintext) {
    return [
      `Version: ${container.version}`,
      `Header length: ${container.headerLength} bytes`,
      `Save count: ${container.saveCount}`,
      `Password index: ${container.passwordIndex.toString()}`,
      `Salt: ${Array.from(container.salt).map((value) => value.toString(16).padStart(2, "0")).join("")}`,
      `Ciphertext: ${formatBytes(container.ciphertext.length)}`,
      `GUID: ${Array.from(container.guid).map((value) => value.toString(16).padStart(2, "0")).join("")}`,
      `Extension: ${container.extension.length ? Array.from(container.extension).map((value) => value.toString(16).padStart(2, "0")).join("") : "(none)"}`,
      `Decrypted payload: ${formatBytes(plaintext.length)}`,
      "",
      "PBKDF2-HMAC-SHA1 / 10 iterations -> AES-128-CBC -> PKCS#7 -> zlib",
    ].join("\n");
  }

  function loadBytes(bytes, fileName) {
    setStatus(`Reading ${fileName}...`);
    try {
      const decoded = decryptSave(bytes, PASSWORD);
      const payload = decodePayload(decoded.plaintext);
      state.fileName = fileName;
      state.originalBytes = bytes;
      state.originalPlaintext = decoded.plaintext;
      state.container = decoded.container;
      state.object = payload.object;
      state.rawText = payload.text;
      state.isJson = payload.isJson;
      state.keepBom = payload.keepBom;
      state.dirty = false;
      updateLoadedUI();
      setStatus("SUCCESS: compatible Ninja Kiwi container detected and decrypted.", "success");
      showToast("Profile loaded. Changes stay in this browser tab.", "success");
    } catch (error) {
      setStatus("ERROR: file could not be detected or decrypted.", "error");
      showToast(error.message || "Could not open this save.", "error");
    }
  }

  async function loadFile(file) {
    if (!file) return;
    loadBytes(new Uint8Array(await file.arrayBuffer()), file.name);
  }

  function getEditedPlaintext() {
    if (state.mode === "raw") {
      const text = dom.rawEditor.value;
      if (state.isJson) {
        try {
          JSON.parse(text);
        } catch (error) {
          throw new Error(`JSON is invalid: ${error.message}`);
        }
      }
      return encodeText(text, state.keepBom);
    }
    if (!state.object) return encodeText(state.rawText, state.keepBom);
    return encodeText(JSON.stringify(state.object, null, 2), state.keepBom);
  }

  function assertVerifiedExport(newBytes, intendedPlaintext) {
    const verified = decryptSave(newBytes, PASSWORD);
    if (!bytesEqual(verified.plaintext, intendedPlaintext)) {
      throw new Error("Verification failed: generated save did not decrypt to the intended payload.");
    }
    if (verified.container.version !== state.container.version) throw new Error("Verification failed: header version changed.");
    if (verified.container.headerLength !== state.container.headerLength) throw new Error("Verification failed: header length changed.");
    if (!bytesEqual(verified.container.guid, state.container.guid)) throw new Error("Verification failed: GUID changed.");
    if (!bytesEqual(verified.container.unknown, state.container.unknown)) throw new Error("Verification failed: unknown header field changed.");
    if (!bytesEqual(verified.container.extension, state.container.extension)) throw new Error("Verification failed: header extension changed.");
    if (verified.container.passwordIndex !== state.container.passwordIndex) throw new Error("Verification failed: password index changed.");
    if (verified.container.saveCount !== state.container.saveCount + 1) throw new Error("Verification failed: save count was not incremented.");
    return verified;
  }

  function bytesEqual(left, right) {
    if (!left || !right || left.length !== right.length) return false;
    for (let index = 0; index < left.length; index += 1) if (left[index] !== right[index]) return false;
    return true;
  }

  function downloadEditedSave() {
    if (!state.originalBytes || !state.container) return;
    try {
      const plaintext = getEditedPlaintext();
      const newBytes = encryptSave(plaintext, state.container, PASSWORD);
      const verified = assertVerifiedExport(newBytes, plaintext);
      const stem = state.fileName.replace(/\.[^.]+$/, "") || "Profile";
      const outputName = `${stem}_edited.Save`;
      const blob = new Blob([newBytes], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = outputName;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      state.dirty = false;
      updateDirtyUI();
      setStatus(`SUCCESS: ${outputName} was encrypted, verified, and downloaded.`, "success");
      showToast(`Export verified. Save count is now ${verified.container.saveCount}.`, "success");
    } catch (error) {
      setStatus("ERROR: export was not written.", "error");
      showToast(error.message || "Could not create an edited save.", "error");
    }
  }

  function verifySource() {
    if (!state.originalBytes) return;
    try {
      const verified = decryptSave(state.originalBytes, PASSWORD);
      if (!bytesEqual(verified.plaintext, state.originalPlaintext)) throw new Error("Decrypted bytes changed unexpectedly.");
      setStatus("Verification PASSED: the original file decrypts and decompresses correctly.", "success");
      showToast("Original Profile.Save verified.", "success");
    } catch (error) {
      setStatus("Verification FAILED.", "error");
      showToast(error.message, "error");
    }
  }

  function resetToSource() {
    if (!state.originalBytes) return;
    if (state.dirty && !window.confirm("Discard all edits and re-decrypt the original file?")) return;
    try {
      const decoded = decryptSave(state.originalBytes, PASSWORD);
      const payload = decodePayload(decoded.plaintext);
      state.container = decoded.container;
      state.originalPlaintext = decoded.plaintext;
      state.object = payload.object;
      state.rawText = payload.text;
      state.isJson = payload.isJson;
      state.keepBom = payload.keepBom;
      state.dirty = false;
      updateLoadedUI();
      setStatus("Re-decrypted the untouched original file.", "success");
    } catch (error) {
      setStatus("ERROR: could not re-decrypt the original file.", "error");
      showToast(error.message, "error");
    }
  }

  function clearAll() {
    state.fileName = "";
    state.originalBytes = null;
    state.originalPlaintext = null;
    state.container = null;
    state.object = null;
    state.rawText = "";
    state.isJson = false;
    state.keepBom = false;
    state.mode = "normal";
    state.dirty = false;
    dom.fileInput.value = "";
    dom.verifyButton.disabled = true;
    dom.resetButton.disabled = true;
    dom.downloadButton.disabled = true;
    dom.clearButton.disabled = true;
    dom.editorView.hidden = true;
    dom.welcomeView.hidden = false;
    setStatus("Ready. Your file stays in this browser tab.");
  }

  function selectAllRaw() {
    dom.rawEditor.focus();
    dom.rawEditor.select();
  }

  dom.openButton.addEventListener("click", () => dom.fileInput.click());
  dom.fileInput.addEventListener("change", () => loadFile(dom.fileInput.files[0]));
  dom.verifyButton.addEventListener("click", verifySource);
  dom.resetButton.addEventListener("click", resetToSource);
  dom.downloadButton.addEventListener("click", downloadEditedSave);
  dom.clearButton.addEventListener("click", clearAll);
  dom.selectAllButton.addEventListener("click", selectAllRaw);
  dom.rawEditor.addEventListener("input", () => {
    state.rawText = dom.rawEditor.value;
    markDirty();
    if (state.isJson) {
      try {
        JSON.parse(state.rawText);
        setRawValidation("JSON is valid and ready to export.", "success");
      } catch (error) {
        setRawValidation(`Invalid JSON: ${error.message}`, "error");
      }
    } else setRawValidation("Plain UTF-8 text is ready to export.", "success");
  });
  dom.modeButtons.forEach((button) => button.addEventListener("click", () => switchMode(button.dataset.mode)));

  ["dragenter", "dragover"].forEach((eventName) => dom.welcomeView.addEventListener(eventName, (event) => {
    event.preventDefault();
    dom.welcomeView.classList.add("is-dragging");
  }));
  ["dragleave", "drop"].forEach((eventName) => dom.welcomeView.addEventListener(eventName, (event) => {
    event.preventDefault();
    dom.welcomeView.classList.remove("is-dragging");
  }));
  dom.welcomeView.addEventListener("drop", (event) => loadFile(event.dataTransfer.files[0]));

  window.BBSE = {
    constants: { PASSWORD, PBKDF2_ITERATIONS, SALT_LENGTH, AES_BLOCK_LENGTH },
    state,
    parseContainer,
    decryptSave,
    encryptSave,
    decodePayload,
    encodeText,
    bytesEqual,
    loadBytes,
    getEditedPlaintext,
    assertVerifiedExport,
  };
})();