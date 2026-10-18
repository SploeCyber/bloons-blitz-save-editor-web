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
  const MAX_ENTITY_LEVEL = 20;
  const MAX_RANK_LEVEL = 49;

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
    rawInvalid: false,
  };

  const dom = {
    welcomeView: document.querySelector("#welcomeView"),
    editorView: document.querySelector("#editorView"),
    fileInput: document.querySelector("#fileInput"),
    openButton: document.querySelector("#openButton"),
    verifyButton: document.querySelector("#verifyButton"),
    resetButton: document.querySelector("#resetButton"),
    downloadButton: document.querySelector("#downloadButton"),
    fileName: document.querySelector("#fileName"),
    fileMeta: document.querySelector("#fileMeta"),
    normalEditor: document.querySelector("#normalEditor"),
    rawEditorPanel: document.querySelector("#rawEditorPanel"),
    rawEditor: document.querySelector("#rawEditor"),
    rawValidation: document.querySelector("#rawValidation"),
    syncState: document.querySelector("#syncState"),
    searchInput: document.querySelector("#searchInput"),
    searchCount: document.querySelector("#searchCount"),
    metadataText: document.querySelector("#metadataText"),
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

  const CATALOG = window.BBSE_CATALOG || {};

  function fieldDescriptor(path, label, fallback, kind, options = {}) {
    return { path, label, fallback, kind, catalog: options.catalog };
  }

  let listSeq = 0;

  function catalogLabel(group, identifier) {
    const list = CATALOG[group];
    if (!Array.isArray(list)) return null;
    const hit = list.find((entry) => entry.id === identifier);
    return hit ? hit.label : null;
  }

  function dotnetTicksNow() {
    return (DOTNET_UNIX_EPOCH_UTC + BigInt(Date.now()) * DOTNET_TICKS_PER_MS).toString();
  }

  const TEMPLATES = {
    hero: (id) => ({
      id,
      overallXPSpent: 0,
      currentXP: 0,
      level: 1,
      availableStickerSquares: 0,
      unlockedStickerSquares: [],
      pending: -1,
      levelChoices: ["default"],
      newlyUnlockedInGameUpgrades: [],
      loadout_: [],
      heroPowerLevel: 0,
    }),
    monkey: (id) => ({
      id,
      overallXPSpent: 0,
      currentXP: 0,
      level: 1,
      pending: -1,
      powerLevel: 0,
      levelChoices: ["default"],
      newlyUnlockedInGameUpgrades: [],
    }),
    sticker: (id) => ({ id, unlockTime: dotnetTicksNow(), level: 1 }),
    toy: (id) => ({ id, count: 1 }),
    consumable: (id) => ({ id, count: 1 }),
    trade: () => ({ offeringToyId: "", offeringAmount: 1, tradingToyId: "", tradingAmount: 1 }),
  };

  function attachDatalist(input, group, parent) {
    const known = CATALOG[group] || [];
    if (!known.length) return;
    const listId = `dl-${group}-${(listSeq += 1)}`;
    const list = document.createElement("datalist");
    list.id = listId;
    known.forEach((entry) => {
      const option = document.createElement("option");
      option.value = entry.id;
      option.label = entry.label;
      list.append(option);
    });
    input.setAttribute("list", listId);
    (parent || input.parentNode || input).append(list);
  }

  function ensureArray(path) {
    const current = getPath(state.object, path, null);
    if (Array.isArray(current)) return current;
    const created = [];
    setPath(state.object, path, created);
    return created;
  }

  function addIdList(parent, path, label, catalogGroup) {
    const wrap = makeElement("div", "list-editor");
    wrap.title = path.join(".");
    const head = makeElement("div", "field");
    head.append(makeElement("span", "field-label", label));
    wrap.append(head);
    const chips = makeElement("div", "chips");
    wrap.append(chips);
    parent.append(wrap);

    const renderChips = () => {
      clearElement(chips);
      const list = ensureArray(path);
      if (!list.length) chips.append(makeElement("span", "empty", "None"));
      list.forEach((value, index) => {
        const chip = makeElement("span", "chip");
        const knownLabel = catalogLabel(catalogGroup, value);
        chip.append(makeElement("span", "chip-text", knownLabel ? `${knownLabel}` : String(value)));
        chip.title = String(value);
        const remove = makeElement("button", "chip-x", "×");
        remove.type = "button";
        remove.title = "Remove";
        remove.addEventListener("click", () => {
          ensureArray(path).splice(index, 1);
          markDirty();
          renderChips();
        });
        chip.append(remove);
        chips.append(chip);
      });
      const adder = makeElement("div", "chip-add");
      const input = document.createElement("input");
      input.type = "text";
      input.placeholder = "Add id…";
      input.spellcheck = false;
      input.autocomplete = "off";
      const button = makeElement("button", "chip-add-btn", "Add");
      button.type = "button";
      adder.append(input, button);
      attachDatalist(input, catalogGroup, adder);
      chips.append(adder);
      const commit = () => {
        const value = input.value.trim();
        if (!value) return;
        ensureArray(path).push(value);
        markDirty();
        renderChips();
      };
      button.addEventListener("click", commit);
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
        }
      });
      adder.append(input, button);
      chips.append(adder);
    };
    renderChips();
  }

  function buildIdInput(parent, descriptor, value, onChange) {
    const wrap = makeElement("span", "id-input");
    const input = document.createElement("input");
    input.type = "text";
    input.value = value === null || value === undefined ? "" : String(value);
    input.spellcheck = false;
    input.autocomplete = "off";
    const known = CATALOG[descriptor.catalog] || [];
    const label = catalogLabel(descriptor.catalog, input.value);
    if (label) input.title = label;

    if (known.length) {
      const listId = `ids-${descriptor.catalog}-${(listSeq += 1)}`;
      const list = document.createElement("datalist");
      list.id = listId;
      known.forEach((entry) => {
        const option = document.createElement("option");
        option.value = entry.id;
        option.label = entry.label;
        list.append(option);
      });
      input.setAttribute("list", listId);
      wrap.append(list);
    }
    input.addEventListener("change", () => {
      const nextLabel = catalogLabel(descriptor.catalog, input.value);
      input.title = nextLabel || "";
      onChange(input.value);
    });
    wrap.append(input);
    parent.append(wrap);
  }

  function addSection(parent, title, options = {}) {
    const section = makeElement("section", `section${options.wide ? " is-wide" : ""}`);
    section.append(makeElement("h2", "", title));
    parent.append(section);
    return section;
  }

  function quickAction(parent, label, hint, run) {
    const button = makeElement("button", "quick-action");
    button.type = "button";
    button.append(makeElement("span", "quick-action-label", label));
    if (hint) button.append(makeElement("span", "quick-action-hint", hint));
    button.addEventListener("click", run);
    parent.append(button);
    return button;
  }

  function addQuickActions(parent) {
    const wrap = makeElement("div", "quick-actions");
    const existingIds = (path, idKey = "id") => {
      const list = getPath(state.object, path, []);
      return new Set((Array.isArray(list) ? list : []).map((item) => item && item[idKey]).filter(Boolean));
    };

    const missing = (path, catalog, idKey = "id") => (catalog || [])
      .filter((entry) => !existingIds(path, idKey).has(entry.id))
      .map((entry) => entry.id);

    quickAction(wrap, "Unlock every hero", "adds missing heroes", () => {
      const heroes = missing(["heroes"], CATALOG.heroes);
      heroes.forEach((id) => ensureArray(["heroes"]).push(TEMPLATES.hero(id)));
      finishQuick(heroes.length, "hero");
    });

    quickAction(wrap, "Unlock every monkey", "adds missing monkeys", () => {
      const monkeys = missing(["monkeys"], CATALOG.monkeys);
      monkeys.forEach((id) => ensureArray(["monkeys"]).push(TEMPLATES.monkey(id)));
      finishQuick(monkeys.length, "monkey");
    });

    quickAction(wrap, "Unlock every sticker", "adds missing stickers", () => {
      const stickers = missing(["ownedGear"], CATALOG.stickers);
      stickers.forEach((id) => ensureArray(["ownedGear"]).push(TEMPLATES.sticker(id)));
      // "Used ever" means the sticker has been equipped at least once, so every
      // catalog entry belongs there once the whole set is unlocked.
      (CATALOG.stickers || []).forEach((entry) => {
        ["stickersUsedEver", "chosenStickersPendingFirstTimeBonus"].forEach((path) => {
          const list = ensureArray(path);
          if (!list.includes(entry.id)) list.push(entry.id);
        });
      });
      finishQuick(stickers.length, "sticker");
    });

    quickAction(wrap, "Max every level", "levels, power and XP", () => {
      let touched = 0;
      const bump = (list, fields, value) => {
        (Array.isArray(list) ? list : []).forEach((item) => {
          if (!item || typeof item !== "object") return;
          fields.forEach((field) => {
            if (typeof item[field] === "number") item[field] = value;
          });
          touched += 1;
        });
      };
      bump(state.object.heroes, ["level", "heroPowerLevel"], MAX_ENTITY_LEVEL);
      bump(state.object.monkeys, ["level", "powerLevel"], MAX_ENTITY_LEVEL);
      const rank = getPath(state.object, ["playerRank"], {});
      rank.level = MAX_RANK_LEVEL;
      rank.levelCap = MAX_RANK_LEVEL;
      rank.xp = 9999999;
      ["playerLevel", "playerPowerLevel", "playerLevelProgress"].forEach((key) => {
        if (typeof state.object[key] === "number") state.object[key] = MAX_ENTITY_LEVEL;
      });
      finishQuick(touched, "unit");
    });

    quickAction(wrap, "Refill currencies", "money, stones, lives", () => {
      const currencies = getPath(state.object, ["currencies"], {});
      currencies.monkeyMoney = 9999999;
      currencies.bloonStones = 9999;
      currencies.lives = 9999;
      finishQuick(Object.keys(currencies).length, "currency");
    });

    parent.append(wrap);
  }

  function finishQuick(count, noun) {
    markDirty();
    renderNormalEditor();
    showToast(count > 0 ? `Updated ${count} ${noun}${count === 1 ? "" : "s"}.` : `Nothing to change.`, count > 0 ? "success" : "neutral");
  }

  function addField(parent, descriptor) {
    const row = makeElement("label", "field");
    const label = makeElement("span", "field-label", descriptor.label);
    row.title = descriptor.path.join(".");
    const value = getPath(state.object, descriptor.path, descriptor.fallback);
    const kind = inferKind(value, descriptor.kind);
    let input;
    if (descriptor.catalog) {
      buildIdInput(row, descriptor, value, (next) => {
        setPath(state.object, descriptor.path, next);
        markDirty();
      });
      row.append(label, row.lastChild);
      parent.append(row);
      return;
    }
    if (kind === "boolean") {
      input = document.createElement("input");
      input.type = "checkbox";
      input.checked = Boolean(value);
    } else {
      input = document.createElement("input");
      input.type = kind === "number" ? "number" : "text";
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
      parent.append(makeElement("div", "empty", "None"));
      return;
    }
    entries.forEach(([key, value]) => {
      if (key === "id" || key === "Id" || key === "key" || key === "name") return;
      addField(parent, fieldDescriptor([...objectPath, key], `${labelPrefix}${key}`, value, inferKind(value)));
    });
  }

  function addCollection(parent, title, path, options = {}) {
    const collection = makeElement("div", "collection");
    collection.append(makeElement("div", "collection-label", title));
    const items = getPath(state.object, path, []);
    if (!Array.isArray(items)) {
      collection.append(makeElement("div", "empty", "Not a list"));
      parent.append(collection);
      return;
    }
    if (!items.length) collection.append(makeElement("div", "empty", "None"));
    items.forEach((item, index) => {
      const block = makeElement("div", "item");
      const identifier = itemIdentifier(item, index);
      const knownName = options.catalog ? catalogLabel(options.catalog, identifier) : null;
      block.append(makeElement("div", "item-name", knownName || identifier));
      if (options.catalog && item && typeof item === "object" && (options.idKey || "id") in item) {
        const key = options.idKey || "id";
        addField(block, fieldDescriptor([...path, index, key], "ID", identifier, "text", { catalog: options.catalog }));
      }
      if (options.fields) {
        const descriptors = options.fields.map((field) => fieldDescriptor([...path, index, field.path], field.label, field.fallback, field.kind, { catalog: field.catalog }));
        addFields(block, descriptors);
      } else {
        addObjectFields(block, [...path, index], item);
      }
      collection.append(block);
    });
    if (options.add) addCollectionBar(collection, path, options.add, options.fields);
    parent.append(collection);
  }

  function addCollectionBar(collection, path, add, fields) {
    const bar = makeElement("div", "collection-add");
    const input = document.createElement("input");
    input.type = "text";
    input.placeholder = add.placeholder || "Add id…";
    input.spellcheck = false;
    input.autocomplete = "off";
    input.className = "field-input";
    const button = makeElement("button", "chip-add-btn", add.button || "Add");
    button.type = "button";
    bar.append(input, button);
    if (add.catalog) attachDatalist(input, add.catalog, bar);
    const commit = () => {
      const value = input.value.trim();
      if (!value) return;
      const list = ensureArray(path);
      if (add.template) list.push(add.template(value));
      else if (fields) {
        const item = {};
        fields.forEach((field) => {
          const target = field.path.length === 1 ? item : (item[field.path[0]] ??= {});
          const leaf = field.path[field.path.length - 1];
          target[leaf] = field.fallback;
        });
        item[fields[0].path[0]] = value;
        list.push(item);
      } else list.push(value);
      input.value = "";
      markDirty();
      renderNormalEditor();
    };
    button.addEventListener("click", commit);
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        commit();
      }
    });
    bar.append(input, button);
    collection.append(bar);
  }

  function addMapProgression(parent) {
    const mapCatalog = (CATALOG.map && CATALOG.map.biomes) || [];
    if (!mapCatalog.length) return;

    const wrap = makeElement("div", "collection");
    wrap.append(makeElement("div", "collection-label", "Map progression"));

    const biomes = ensureArray(["mapData", "unlockedMapBiomes"]);
    const biomeIndex = new Map();
    biomes.forEach((entry, index) => {
      if (entry && entry.Id) biomeIndex.set(entry.Id, { entry, index });
    });

    const bar = makeElement("div", "collection-add");
    const unlockAll = makeElement("button", "chip-add-btn", "Unlock every biome and level");
    unlockAll.type = "button";
    unlockAll.addEventListener("click", () => {
      let addedBiomes = 0;
      let addedRoutes = 0;
      let addedLevels = 0;
      mapCatalog.forEach((biome) => {
        let record = biomeIndex.get(biome.id);
        if (!record) {
          const entry = { Id: biome.id, unlockedRoutes: [], unlockedSpecialLevels: {} };
          ensureArray(["mapData", "unlockedMapBiomes"]).push(entry);
          record = { entry, index: ensureArray(["mapData", "unlockedMapBiomes"]).length - 1 };
          biomeIndex.set(biome.id, record);
          addedBiomes += 1;
        }
        const routes = ensureArray(["mapData", "unlockedMapBiomes", record.index, "unlockedRoutes"]);
        const routeIndex = new Map();
        routes.forEach((route, index) => {
          if (route && route.Id) routeIndex.set(route.Id, index);
        });
        biome.routes.forEach((route) => {
          let routePos = routeIndex.get(route.id);
          if (routePos === undefined) {
            routes.push({ Id: route.id, unlockedLevels: [] });
            routePos = routes.length - 1;
            routeIndex.set(route.id, routePos);
            addedRoutes += 1;
          }
          const levels = ensureArray(["mapData", "unlockedMapBiomes", record.index, "unlockedRoutes", routePos, "unlockedLevels"]);
          for (let index = levels.length; index < route.levels; index += 1) {
            levels.push(makeUnlockedLevel(index));
            addedLevels += 1;
          }
        });
      });
      markDirty();
      renderNormalEditor();
      showToast(`Unlocked ${addedBiomes} biome(s), ${addedRoutes} route(s), ${addedLevels} level(s).`, "success");
    });
    bar.append(unlockAll);
    wrap.append(bar);

    mapCatalog.forEach((biome) => {
      const record = biomeIndex.get(biome.id);
      const block = makeElement("div", "item");
      const unlockedRoutes = record ? getPath(state.object, ["mapData", "unlockedMapBiomes", record.index, "unlockedRoutes"], []) : [];
      const unlockedLevels = (Array.isArray(unlockedRoutes) ? unlockedRoutes : [])
        .reduce((total, route) => total + (Array.isArray(route.unlockedLevels) ? route.unlockedLevels.length : 0), 0);
      const totalLevels = biome.routes.reduce((total, route) => total + route.levels, 0);
      block.append(makeElement("div", "item-name", `${biome.label} · ${unlockedLevels}/${totalLevels} levels`));

      const rows = makeElement("div", "map-rows");
      biome.routes.forEach((route) => {
        const routePos = Array.isArray(unlockedRoutes)
          ? unlockedRoutes.findIndex((entry) => entry && entry.Id === route.id)
          : -1;
        const row = makeElement("div", "map-row");
        const rowTitle = makeElement("span", "map-row-title", route.label);
        row.append(rowTitle);
        if (routePos === -1) {
          const button = makeElement("button", "chip-add-btn", "Unlock");
          button.type = "button";
          button.addEventListener("click", () => {
            if (!biomeIndex.has(biome.id)) {
              ensureArray(["mapData", "unlockedMapBiomes"]).push({ Id: biome.id, unlockedRoutes: [], unlockedSpecialLevels: {} });
              biomeIndex.set(biome.id, { index: ensureArray(["mapData", "unlockedMapBiomes"]).length - 1 });
            }
            const target = biomeIndex.get(biome.id).index;
            const levels = [];
            for (let index = 0; index < route.levels; index += 1) levels.push(makeUnlockedLevel(index));
            ensureArray(["mapData", "unlockedMapBiomes", target, "unlockedRoutes"]).push({ Id: route.id, unlockedLevels: levels });
            markDirty();
            renderNormalEditor();
            showToast(`Unlocked ${biome.label} ${route.label}.`, "success");
          });
          row.append(button);
        } else {
          const levels = getPath(state.object, ["mapData", "unlockedMapBiomes", record.index, "unlockedRoutes", routePos, "unlockedLevels"], []);
          const count = Array.isArray(levels) ? levels.length : 0;
          row.append(makeElement("span", "map-row-note", count >= route.levels ? "complete" : `${count}/${route.levels}`));
          const addLevel = makeElement("button", "chip-add-btn", "Add level");
          addLevel.type = "button";
          addLevel.disabled = count >= route.levels;
          addLevel.addEventListener("click", () => {
            const target = ensureArray(["mapData", "unlockedMapBiomes", record.index, "unlockedRoutes", routePos, "unlockedLevels"]);
            target.push(makeUnlockedLevel(count));
            markDirty();
            renderNormalEditor();
          });
          row.append(addLevel);
        }
        rows.append(row);
      });
      block.append(rows);
      wrap.append(block);
    });
    parent.append(wrap);
  }

  function makeUnlockedLevel(index) {
    return {
      mainLevelData: {
        completed: false,
        bestTime: 0,
        quickestTime: 0,
        mostPops: 0,
        mostXP: 0,
        fewestDeaths: 0,
        mostDamage: 0,
        longestDistance: 0,
        checkpointsReached: -1,
        IsNeverAttempted: true,
      },
      challengesData: [],
      viewedUnlockCeremony: false,
      viewedCompletedCeremony: false,
      viewedChallengeDetails: false,
    };
  }

  function renderNormalEditor() {
    clearElement(dom.normalEditor);
    const grid = makeElement("div", "form-grid");
    dom.normalEditor.append(grid);
    if (!state.isJson || !state.object) {
      const section = addSection(grid, "Guided edit unavailable", { wide: true });
      section.append(makeElement("div", "empty", "This payload is plain text. Use Source JSON instead."));
      return;
    }
    buildSections(grid);
    applyFilter();
  }

  function buildSections(grid) {
    const general = addSection(grid, "General & currencies");
    addQuickActions(general);
    addFields(general, [
      fieldDescriptor(["playerLevel"], "Player level", 1, "number"),
      fieldDescriptor(["playerLevelProgress"], "Level progress", 0, "number"),
      fieldDescriptor(["playerPowerLevel"], "Player power level", 1, "number"),
      fieldDescriptor(["currentHeroId"], "Current hero", "", "text", { catalog: "heroes" }),
      fieldDescriptor(["selectedLanguage"], "Language", "English", "text"),
      fieldDescriptor(["completedFirstLevel"], "Completed first level", false, "boolean"),
      fieldDescriptor(["acceptedTermsOfService"], "Accepted terms", false, "boolean"),
    ]);
    const currencies = getPath(state.object, ["currencies"], {});
    Object.entries(currencies && typeof currencies === "object" ? currencies : {}).forEach(([key, value]) => {
      addField(general, fieldDescriptor(["currencies", key], key, value, "number"));
    });

    const metadata = addSection(grid, "Metadata & info");
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

    const monkeys = addSection(grid, "Monkeys", { wide: true });
    addCollection(monkeys, "Monkeys", ["monkeys"], { catalog: "monkeys", fields: [
      { path: ["level"], label: "Level", fallback: 1, kind: "number" },
      { path: ["currentXP"], label: "Current XP", fallback: 0, kind: "number" },
      { path: ["powerLevel"], label: "Power level", fallback: 0, kind: "number" },
    ], add: { catalog: "monkeys", template: TEMPLATES.monkey, button: "Add monkey" } });

    const heroes = addSection(grid, "Heroes & gear", { wide: true });
    addCollection(heroes, "Heroes", ["heroes"], { catalog: "heroes", fields: [
      { path: ["level"], label: "Level", fallback: 1, kind: "number" },
      { path: ["heroPowerLevel"], label: "Power level", fallback: 0, kind: "number" },
      { path: ["currentXP"], label: "Current XP", fallback: 0, kind: "number" },
      { path: ["overallXPSpent"], label: "XP spent", fallback: 0, kind: "number" },
      { path: ["pending"], label: "Pending level", fallback: -1, kind: "number" },
      { path: ["availableStickerSquares"], label: "Sticker squares", fallback: 0, kind: "number" },
    ], add: { catalog: "heroes", template: TEMPLATES.hero, button: "Unlock hero" } });
    addCollection(heroes, "Owned stickers", ["ownedGear"], { catalog: "stickers", fields: [
      { path: ["level"], label: "Level", fallback: 1, kind: "number" },
    ], add: { catalog: "stickers", template: TEMPLATES.sticker, button: "Unlock sticker" } });

    const inventory = addSection(grid, "Inventory", { wide: true });
    addCollection(inventory, "Consumables", ["consumables"], { catalog: "consumables", fields: [
      { path: ["count"], label: "Count", fallback: 0, kind: "number" },
    ], add: { catalog: "consumables", template: TEMPLATES.consumable, button: "Add consumable" } });
    addCollection(inventory, "Toys", ["toys"], { catalog: "toys", fields: [
      { path: ["count"], label: "Count", fallback: 0, kind: "number" },
    ], add: { catalog: "toys", template: TEMPLATES.toy, button: "Add toy" } });
    addCollection(inventory, "Spent toys", ["spentToys"], { catalog: "toys", fields: [
      { path: ["count"], label: "Count", fallback: 0, kind: "number" },
    ], add: { catalog: "toys", template: TEMPLATES.toy, button: "Add spent toy" } });


    const missions = addSection(grid, "Missions & FTUE", { wide: true });
    addCollection(missions, "Daily missions", ["profileDailyMissions", "currentMissions"], { fields: [
      { path: ["count"], label: "Count", fallback: 0, kind: "number" },
    ] });
    const ftue = getPath(state.object, ["ftueProgress"], {});
    const ftueBlock = makeElement("div", "collection");
    ftueBlock.append(makeElement("div", "collection-label", "FTUE progress"));
    addObjectFields(ftueBlock, ["ftueProgress"], ftue);
    missions.append(ftueBlock);

    const map = addSection(grid, "Map & progress", { wide: true });
    const lastUnlocked = getPath(state.object, ["lastUnlockedLevel"], {});
    const selectedMap = getPath(state.object, ["selectedMapLevel"], {});
    const lastBlock = makeElement("div", "collection");
    lastBlock.append(makeElement("div", "collection-label", "Last unlocked level"));
    addObjectFields(lastBlock, ["lastUnlockedLevel"], lastUnlocked);
    map.append(lastBlock);
    const selectedBlock = makeElement("div", "collection");
    selectedBlock.append(makeElement("div", "collection-label", "Selected map level"));
    addObjectFields(selectedBlock, ["selectedMapLevel"], selectedMap);
    map.append(selectedBlock);
    addMapProgression(map);

    const upgrades = addSection(grid, "Upgrades & stickers", { wide: true });
    addIdList(upgrades, ["upgradesChosenEver"], "Upgrades chosen ever", "upgrades");
    addIdList(upgrades, ["chosenUpgradesPendingFirstTimeBonus"], "Pending first-time bonus", "upgrades");
    addIdList(upgrades, ["stickersUsedEver"], "Stickers used ever", "stickers");
    addIdList(upgrades, ["chosenStickersPendingFirstTimeBonus"], "Sticker bonus pending", "stickers");
    addIdList(inventory, ["toysViewed"], "Toys viewed", "toys");

    const loot = addSection(grid, "Loot & rewards", { wide: true });
    addCollection(loot, "Loot boxes", ["lootBoxes"]);
    addCollection(loot, "Loot box keys", ["lootBoxKeys"]);
    addCollection(loot, "Reward tracking", ["rewardTrackingData"], { fields: [
      { path: ["opened"], label: "Opened", fallback: 0, kind: "number" },
    ] });

    const misc = addSection(grid, "Trading, stats & misc", { wide: true });
    addFields(misc, [
      fieldDescriptor(["runCount"], "Run count", 0, "number"),
      fieldDescriptor(["numLevelsCompleted"], "Levels completed", 0, "number"),
      fieldDescriptor(["numGamesQuit"], "Games quit", 0, "number"),
      fieldDescriptor(["stats", "winStreak"], "Win streak", 0, "number"),
      fieldDescriptor(["lastToyTradingResetTime"], "Toy trading reset", "", "text"),
      fieldDescriptor(["lastSeenTradeEventOffered"], "Last trade event", "", "text"),
    ]);
    addCollection(misc, "Hero trading toys", ["heroTradingToys"], { fields: [
      { path: ["offeringToyId"], label: "Offering toy", fallback: "", kind: "text", catalog: "toys" },
      { path: ["offeringAmount"], label: "Offering amount", fallback: 1, kind: "number" },
      { path: ["tradingToyId"], label: "Target toy", fallback: "", kind: "text", catalog: "toys" },
      { path: ["tradingAmount"], label: "Target amount", fallback: 1, kind: "number" },
    ], add: { template: TEMPLATES.trade, button: "Add trade" } });

    const ads = getPath(state.object, ["adWatchTracking"], {});
    const adBlock = makeElement("div", "collection");
    adBlock.append(makeElement("div", "collection-label", "Ad watch tracking"));
    Object.entries(ads && typeof ads === "object" ? ads : {}).forEach(([key, value]) => {
      addField(adBlock, fieldDescriptor(["adWatchTracking", key, "numberOfWatchesThisPeriod"], key, value?.numberOfWatchesThisPeriod ?? 0, "number"));
    });
    misc.append(adBlock);

    const shop = addSection(grid, "Shop & purchases");
    addFields(shop, [
      fieldDescriptor(["orderInTransit"], "Order in transit", false, "boolean"),
      fieldDescriptor(["inTransitOrderID"], "In-transit order ID", "", "text"),
      fieldDescriptor(["inTransitOrderContext"], "In-transit order context", "", "text"),
    ]);
    const purchaseFields = purchaseFieldDescriptors();
    addCollection(shop, "Purchases", ["purchases"], { fields: purchaseFields, add: {
      catalog: "products",
      placeholder: "Add product id…",
      template: (id) => makePurchase(id, purchaseFields),
      button: "Add purchase",
    } });

    const rank = addSection(grid, "Rank, rating & nexus");
    addFields(rank, [
      fieldDescriptor(["playerRank", "xp"], "Rank XP", 0, "number"),
      fieldDescriptor(["playerRank", "level"], "Rank level", 1, "number"),
      fieldDescriptor(["playerRank", "levelCap"], "Rank level cap", 1, "number"),
      fieldDescriptor(["rating", "significantEventCount"], "Rating events", 0, "number"),
      fieldDescriptor(["rating", "appUseCount"], "Rating app uses", 0, "number"),
      fieldDescriptor(["rating", "promptCount"], "Rating prompts", 0, "number"),
      fieldDescriptor(["rating", "ratingPromptLastSeenTime"], "Rating last prompt", "", "text"),
      fieldDescriptor(["rating", "ratingLastPromptVersion"], "Rating prompt version", "", "text"),
      fieldDescriptor(["rating", "neverPromptAgain"], "Never prompt again", false, "boolean"),
      fieldDescriptor(["nexus", "creatorId"], "Nexus creator ID", "", "text"),
      fieldDescriptor(["nexus", "isValid"], "Nexus valid", false, "boolean"),
    ]);

    const daily = addSection(grid, "Daily & energy");
    addFields(daily, [
      fieldDescriptor(["dailyEnergyAdWatchCount"], "Energy ad count", 0, "number"),
      fieldDescriptor(["dailyEnergyAdWatchResetTime"], "Energy ad reset", 0, "number"),
      fieldDescriptor(["lastGeneratedLivesAt"], "Lives generated at", "", "text"),
      fieldDescriptor(["lastDailyMissionResetTime"], "Missions reset at", "", "text"),
      fieldDescriptor(["profileDailyMissions", "expiryTime"], "Mission expiry", 0, "number"),
      fieldDescriptor(["profileDailyMissions", "hasClaimedToday"], "Claimed today", false, "boolean"),
      fieldDescriptor(["profileDailyMissions", "hasClaimedNumber"], "Days claimed", 0, "number"),
    ]);

    const accolades = addSection(grid, "Accolades & stats", { wide: true });
    const accoladeData = getPath(state.object, ["accoladesProgress"], {});
    const accoladeEntries = Object.entries(accoladeData && typeof accoladeData === "object" ? accoladeData : {});
    if (!accoladeEntries.length) accolades.append(makeElement("div", "empty", "None"));
    accoladeEntries.forEach(([key, entry]) => {
      const bare = key.replace(/^(accolade|gameStat)\./, "");
      const words = bare.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(" ");
      const label = words.map((word, index) => (index === 0
        ? word.charAt(0).toUpperCase() + word.slice(1)
        : word.charAt(0).toLowerCase() + word.slice(1))).join(" ");
      addField(accolades, fieldDescriptor(["accoladesProgress", key, "progress"], label, entry?.progress ?? 0, "number"));
    });
  }

  function applyFilter() {
    const query = (dom.searchInput && dom.searchInput.value ? dom.searchInput.value : "").trim().toLowerCase();
    if (!dom.searchCount) return;
    if (!query) {
      [...dom.normalEditor.querySelectorAll("[data-hidden]")].forEach((node) => { node.hidden = false; node.removeAttribute("data-hidden"); });
      dom.searchCount.hidden = true;
      dom.searchCount.textContent = "";
      return;
    }
    let visible = 0;
    dom.normalEditor.querySelectorAll(".section").forEach((section) => {
      let sectionHits = 0;
      section.querySelectorAll(".field, .item, .list-editor, .collection-add, .quick-action").forEach((node) => {
        const haystack = `${node.textContent} ${node.title || ""}`.toLowerCase();
        const hit = haystack.includes(query);
        node.hidden = !hit;
        if (hit) node.removeAttribute("data-hidden");
        else node.setAttribute("data-hidden", "");
        if (hit) sectionHits += 1;
      });
      const title = (section.querySelector("h2") ? section.querySelector("h2").textContent : "").toLowerCase();
      const titleHit = title.includes(query);
      section.hidden = sectionHits === 0 && !titleHit;
      visible += sectionHits;
    });
    dom.searchCount.hidden = false;
    dom.searchCount.textContent = visible ? `${visible} match${visible === 1 ? "" : "es"}` : "No matches";
  }

  function purchaseFieldDescriptors() {
    return [
      { path: ["id"], label: "Purchase id", fallback: "", kind: "text", catalog: "products" },
      { path: ["productId"], label: "Product id", fallback: "", kind: "text", catalog: "products" },
      { path: ["purchaseType"], label: "Type", fallback: "", kind: "text" },
      { path: ["price"], label: "Price", fallback: 0, kind: "number" },
      { path: ["currency"], label: "Currency", fallback: "", kind: "text" },
      { path: ["timestamp"], label: "Timestamp", fallback: "", kind: "text" },
      { path: ["receipt"], label: "Receipt", fallback: "", kind: "text" },
    ];
  }

  function makePurchase(id, fields) {
    const item = {};
    fields.forEach((field) => {
      const leaf = field.path[field.path.length - 1];
      item[leaf] = leaf === "id" ? id : field.fallback;
    });
    return item;
  }


  function markDirty() {
    state.dirty = true;
    if (state.mode === "normal" && state.isJson) syncObjectToRaw();
    updateDirtyUI();
  }

  function setSyncState(label, tone = "neutral") {
    if (!dom.syncState) return;
    dom.syncState.textContent = label;
    dom.syncState.dataset.tone = tone;
  }

  function updateDirtyUI() {
    setSyncState(state.rawInvalid ? "Needs valid JSON" : (state.dirty ? "Edited" : "Synced"), state.rawInvalid ? "error" : "success");
  }

  function setRawValidation(message, tone = "neutral") {
    dom.rawValidation.textContent = message;
    dom.rawValidation.dataset.tone = tone;
  }

  function syncObjectToRaw() {
    if (state.isJson && state.object) {
      state.rawText = JSON.stringify(state.object, null, 2);
      dom.rawEditor.value = state.rawText;
      state.rawInvalid = false;
      setRawValidation("Source JSON is synced with Guided edit.", "success");
      setSyncState("Synced", "success");
    }
  }

  function syncRawToObject() {
    if (!state.isJson) return true;
    try {
      state.object = JSON.parse(dom.rawEditor.value);
      state.rawText = dom.rawEditor.value;
      state.rawInvalid = false;
      renderNormalEditor();
      setRawValidation("Valid JSON. Guided edit is up to date.", "success");
      setSyncState("Synced", "success");
      return true;
    } catch (error) {
      state.rawInvalid = true;
      setRawValidation(`Needs valid JSON: ${error.message}`, "error");
      setSyncState("Needs valid JSON", "error");
      return false;
    }
  }

  function switchMode(mode) {
    if (mode === "normal" && !state.isJson) {
      showToast("Guided edit requires a JSON payload. Use Source JSON for this file.", "error");
      return;
    }
    if (mode === "raw") {
      if (state.mode === "normal") syncObjectToRaw();
      dom.rawEditor.value = state.rawText;
      if (!state.isJson) setRawValidation("Plain UTF-8 text is ready to edit.", "success");
    } else {
      if (state.isJson && state.mode === "raw") {
        if (!syncRawToObject()) {
          showToast("Fix the JSON error before leaving Source JSON.", "error");
          return;
        }
      }
    }
    state.mode = mode;
    dom.normalEditor.hidden = mode !== "normal";
    dom.rawEditorPanel.hidden = mode !== "raw";
    if (dom.searchInput) dom.searchInput.hidden = mode !== "normal";
    if (dom.searchCount) dom.searchCount.hidden = mode !== "normal" || !dom.searchInput.value.trim();
    dom.modeButtons.forEach((button) => {
      const active = button.dataset.mode === mode;
      button.classList.toggle("is-active", active);
      button.setAttribute("aria-selected", String(active));
    });
  }

  function updateLoadedUI() {
    const { container } = state;
    dom.fileName.textContent = state.fileName;
    dom.fileMeta.textContent = [
      formatBytes(state.originalBytes.length),
      state.isJson ? "JSON" : "text",
      `save #${formatCount(container.saveCount)}`,
      `v${container.version}`,
    ].join(" · ");
    dom.metadataText.textContent = metadataSummary(container, state.originalPlaintext);
    dom.editorView.hidden = false;
    dom.welcomeView.hidden = true;
    dom.verifyButton.disabled = false;
    dom.resetButton.disabled = false;
    dom.downloadButton.disabled = false;
    dom.modeButtons.find((button) => button.dataset.mode === "normal").setAttribute("aria-disabled", String(!state.isJson));
    renderNormalEditor();
    dom.rawEditor.value = state.rawText;
    state.mode = state.isJson ? "normal" : "raw";
    switchMode(state.mode);
    updateDirtyUI();
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
      state.rawInvalid = false;
      updateLoadedUI();
      showToast("Profile loaded. Changes stay in this browser tab.", "success");
    } catch (error) {
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
        if (!syncRawToObject()) throw new Error("Source JSON is invalid. Fix it before creating a save.");
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
      const outputName = `${stem}.Save`;
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
      showToast(`Export verified. Save count is now ${verified.container.saveCount}.`, "success");
    } catch (error) {
      showToast(error.message || "Could not create an edited save.", "error");
    }
  }

  function verifySource() {
    if (!state.originalBytes) return;
    try {
      const verified = decryptSave(state.originalBytes, PASSWORD);
      if (!bytesEqual(verified.plaintext, state.originalPlaintext)) throw new Error("Decrypted bytes changed unexpectedly.");
      showToast("Original Profile.Save verified.", "success");
    } catch (error) {
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
      state.rawInvalid = false;
      updateLoadedUI();
    } catch (error) {
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
    state.rawInvalid = false;
    dom.fileInput.value = "";
    dom.verifyButton.disabled = true;
    dom.resetButton.disabled = true;
    dom.downloadButton.disabled = true;
    dom.editorView.hidden = true;
    dom.welcomeView.hidden = false;
  }


  dom.openButton.addEventListener("click", () => dom.fileInput.click());
  dom.fileInput.addEventListener("change", () => loadFile(dom.fileInput.files[0]));
  dom.verifyButton.addEventListener("click", verifySource);
  dom.resetButton.addEventListener("click", resetToSource);
  dom.downloadButton.addEventListener("click", downloadEditedSave);
  dom.rawEditor.addEventListener("input", () => {
    state.rawText = dom.rawEditor.value;
    markDirty();
    if (state.isJson) {
      try {
        state.object = JSON.parse(state.rawText);
        state.rawInvalid = false;
        renderNormalEditor();
        setRawValidation("Valid JSON. Guided edit is up to date.", "success");
        setSyncState("Synced", "success");
      } catch (error) {
        state.rawInvalid = true;
        setRawValidation(`Needs valid JSON: ${error.message}`, "error");
        setSyncState("Needs valid JSON", "error");
      }
    } else {
      setRawValidation("Plain UTF-8 text is ready to export.", "success");
      setSyncState("Synced", "success");
    }
  });
  dom.modeButtons.forEach((button) => button.addEventListener("click", () => switchMode(button.dataset.mode)));
  if (dom.searchInput) dom.searchInput.addEventListener("input", applyFilter);

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
