// agents/binary-loader.js — ELF/PE 二进制加载器（零依赖，纯 JS）
//
// 读取二进制文件，解析基本结构：
//   - 格式识别（ELF / PE / 其他）
//   - 架构（ARM/MIPS/x86/x64）
//   - 字符串表提取（.rodata/.data 节区的可打印字符串）
//   - 符号表提取（若有，含导入函数名）
//
// 不做完整反汇编（那需要 Ghidra/radare2），只提取确定性信息。
// 这是二进制漏洞挖掘的基础——string-extractor 和 danger-scanner 依赖它。

const fs = require("fs");

/**
 * 加载二进制文件
 * @param {string} binaryPath
 * @returns {{format, arch, endian, strings, symbols, size}}
 */
function loadBinary(binaryPath) {
  if (!fs.existsSync(binaryPath)) {
    throw new Error(`二进制文件不存在: ${binaryPath}`);
  }
  const buf = fs.readFileSync(binaryPath);
  const format = detectFormat(buf);
  if (format === "elf") return parseElf(buf, binaryPath);
  if (format === "pe") return parsePe(buf, binaryPath);
  // 兜底：按原始二进制处理（提取字符串）
  return parseRaw(buf, binaryPath);
}

function detectFormat(buf) {
  if (buf.length < 4) return "raw";
  // ELF magic: 0x7F 'E' 'L' 'F'
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return "elf";
  // PE/DOS magic: 'M' 'Z'
  if (buf[0] === 0x4d && buf[1] === 0x5a) return "pe";
  // Mach-O
  if ((buf[0] === 0xfe && buf[1] === 0xed && buf[2] === 0xfa) ||
      (buf[0] === 0xcf && buf[1] === 0xfa && buf[2] === 0xed)) return "macho";
  return "raw";
}

function parseElf(buf, path) {
  const is64 = buf[4] === 2; // EI_CLASS: 1=32bit, 2=64bit
  const endian = buf[5] === 1 ? "little" : "big"; // EI_DATA
  const readU16 = endian === "little" ? (o) => buf.readUInt16LE(o) : (o) => buf.readUInt16BE(o);
  const readU32 = endian === "little" ? (o) => buf.readUInt32LE(o) : (o) => buf.readUInt32BE(o);

  const machine = readU16(0x12);
  const archMap = { 0x03: "x86", 0x28: "arm", 0x3e: "x64", 0xb7: "aarch64", 0x08: "mips" };
  const arch = archMap[machine] || `unknown(0x${machine.toString(16)})`;

  // 提取字符串（扫整个文件找可打印序列）
  const strings = extractStrings(buf);
  // 提取符号（简化：从字符串里找函数名特征）
  const symbols = extractSymbolsFromStrings(strings);

  return { format: "elf", arch, endian, is64, strings, symbols, size: buf.length, path };
}

function parsePe(buf, path) {
  // PE 头在 DOS 头偏移 0x3C 处
  const peOffset = buf.readUInt32LE(0x3c);
  const isPe = buf.slice(peOffset, peOffset + 4).toString("ascii") === "PE\0\0";
  const machine = isPe ? buf.readUInt16LE(peOffset + 4) : 0;
  const archMap = { 0x14c: "x86", 0x8664: "x64", 0x1c0: "arm", 0xaa64: "aarch64" };
  const arch = archMap[machine] || "unknown";
  const strings = extractStrings(buf);
  const symbols = extractSymbolsFromStrings(strings);
  return { format: "pe", arch, endian: "little", strings, symbols, size: buf.length, path };
}

function parseRaw(buf, path) {
  const strings = extractStrings(buf);
  return { format: "raw", arch: "unknown", endian: "unknown", strings, symbols: [], size: buf.length, path };
}

/**
 * 提取可打印字符串（长度 >= 4 的 ASCII 序列）
 */
function extractStrings(buf, minLen = 4) {
  const strings = [];
  let current = "";
  let startOffset = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    // 可打印 ASCII（含 tab）
    if (b >= 0x20 && b <= 0x7e) {
      if (current.length === 0) startOffset = i;
      current += String.fromCharCode(b);
    } else {
      if (current.length >= minLen) {
        strings.push({ value: current, offset: startOffset });
      }
      current = "";
    }
  }
  if (current.length >= minLen) strings.push({ value: current, offset: startOffset });
  return strings;
}

/**
 * 从字符串里提取疑似函数名（符号表的简化版）
 */
function extractSymbolsFromStrings(strings) {
  const symbols = [];
  const seen = new Set();
  for (const s of strings) {
    const v = s.value;
    // 函数名特征：包含 _ 且像 C 函数名（如 strcpy, __libc_start_main）
    if (/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(v) && v.length >= 3 && !seen.has(v)) {
      seen.add(v);
      symbols.push({ name: v, offset: s.offset });
    }
  }
  return symbols;
}

module.exports = { loadBinary, detectFormat, extractStrings };
