// validator.js — 基于 ajv 的 schema 校验工具
// 加载 schemas/ 目录下所有 schema，建立 $ref 跨文件解析，提供统一的校验入口。
// MCP server 在返回结果前调用此模块，确保输出严格符合契约。

const Ajv = require("ajv/dist/2020");
const addFormats = require("ajv-formats");
const fs = require("fs");
const path = require("path");

const SCHEMA_DIR = path.resolve(__dirname, "..", "schemas");

// 加载所有 schema 文件，建立 $id -> schema 映射
function loadSchemas() {
  const schemas = {};
  const files = fs.readdirSync(SCHEMA_DIR).filter((f) => f.endsWith(".schema.json"));
  for (const f of files) {
    const content = JSON.parse(fs.readFileSync(path.join(SCHEMA_DIR, f), "utf-8"));
    schemas[content.$id] = content;
  }
  return schemas;
}

// 初始化 ajv 实例（一次性，复用）
function createValidator() {
  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const schemas = loadSchemas();
  // 先注册所有 schema（建立 $ref 解析）
  for (const [id, schema] of Object.entries(schemas)) {
    try {
      ajv.addSchema(schema, id);
    } catch (e) {
      // 某些 schema 仅作为 $defs 引用，addSchema 可能因无 type 报错，忽略
      if (!String(e.message).includes("doesn't have")) throw e;
    }
  }
  return { ajv, schemas };
}

const { ajv, schemas } = createValidator();

// 已编译校验器缓存
const compiledCache = {};

/**
 * 按 schema 文件名校验数据
 * @param {string} schemaFile  如 "sast-output.schema.json"
 * @param {object} data        待校验数据
 * @returns {{ valid: boolean, errors: array|null }}
 */
function validate(schemaFile, data) {
  const id = `https://ai-vuln-hunter/schemas/${schemaFile}`;
  if (!schemas[id]) {
    return { valid: false, errors: [{ message: `Schema ${schemaFile} 未找到` }] };
  }
  if (!compiledCache[id]) {
    compiledCache[id] = ajv.getSchema(id) || ajv.compile(schemas[id]);
  }
  const valid = compiledCache[id](data);
  return { valid, errors: valid ? null : compiledCache[id].errors };
}

/**
 * 把 ajv 错误对象数组格式化为人类可读字符串
 */
function formatErrors(errors) {
  if (!errors || errors.length === 0) return "无错误";
  return errors
    .map((e) => {
      const loc = e.instancePath || "(root)";
      const param = e.params ? " " + JSON.stringify(e.params) : "";
      return `[${loc}] ${e.message}${param}`;
    })
    .join("\n");
}

module.exports = { validate, formatErrors, schemas };
