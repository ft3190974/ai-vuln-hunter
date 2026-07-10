// agents/call-graph.js — 跨函数调用图（零依赖）
//
// 基于 c-ast-parser 的输出构建调用图：
//   - 节点：函数 {name, file, line, signature}
//   - 边：调用关系 {caller, callee, line}
//
// 提供：
//   getCallers(func)   谁调用了 X（向上追溯）
//   getCallees(func)   X 调用了谁（向下追溯）
//   getCallChain(from, to)  从 A 到 B 的调用链（BFS）
//   serialize(func)    给 LLM 看的文本摘要（函数 + 调用上下文）

class CallGraph {
  constructor() {
    /** @type {Map<string, object>} 函数名 → 函数定义 */
    this.nodes = new Map();
    /** @type {Array<{caller, callee, line, callerFile}>} 调用边 */
    this.edges = [];
    /** @type {Map<string, Array>} callee → callers[] 反向索引 */
    this._reverseIndex = new Map();
  }

  /**
   * 从 c-ast-parser 的结果构建调用图
   * @param {{functions, calls}} parsed
   */
  buildFromParsed(parsed) {
    // 注册函数节点
    for (const fn of parsed.functions || []) {
      // 同名函数取第一个（C 没有 overload，C++ 的 overload 需 full signature 区分，简化处理）
      if (!this.nodes.has(fn.name)) {
        this.nodes.set(fn.name, fn);
      }
    }
    // 注册调用边
    for (const call of parsed.calls || []) {
      this.edges.push(call);
      // 反向索引：callee → caller
      if (!this._reverseIndex.has(call.callee)) {
        this._reverseIndex.set(call.callee, []);
      }
      this._reverseIndex.get(call.callee).push(call);
    }
    return this;
  }

  /** 获取调用 X 的所有函数 */
  getCallers(funcName) {
    return this._reverseIndex.get(funcName) || [];
  }

  /** 获取 X 调用的所有函数 */
  getCallees(funcName) {
    return this.edges.filter((e) => e.caller === funcName);
  }

  /**
   * 获取从 from 到 to 的调用链（BFS，返回路径上的函数序列）
   * 用于回答"数据能否从 A 流到 B"
   */
  getCallChain(from, to, maxDepth = 5) {
    if (from === to) return [from];
    const visited = new Set([from]);
    const queue = [{ name: from, path: [from] }];
    while (queue.length > 0) {
      const { name, path } = queue.shift();
      if (path.length > maxDepth) continue;
      const callees = this.getCallees(name);
      for (const c of callees) {
        if (visited.has(c.callee)) continue;
        const newPath = [...path, c.callee];
        if (c.callee === to) return newPath;
        visited.add(c.callee);
        queue.push({ name: c.callee, path: newPath });
      }
    }
    return null; // 不可达
  }

  /**
   * 给 LLM 生成的文本摘要：函数 + 它的调用上下文（调用了谁 / 被谁调用）
   * 这是 LLM 做跨函数分析的关键输入
   */
  serialize(funcName) {
    const fn = this.nodes.get(funcName);
    if (!fn) return `(未知函数 ${funcName})`;

    const callers = this.getCallers(funcName);
    const callees = this.getCallees(funcName);

    let text = `【函数 ${funcName}】定义于 ${fn.file}:${fn.line}\n`;
    text += `  签名: ${fn.signature}\n`;

    if (callers.length > 0) {
      text += `  被以下函数调用（上游，共 ${callers.length} 处）:\n`;
      for (const c of callers.slice(0, 5)) {
        text += `    - ${c.caller} (${c.callerFile}:${c.line})\n`;
      }
      if (callers.length > 5) text += `    ... 共 ${callers.length} 处\n`;
    } else {
      text += `  被以下函数调用（上游）: 无（可能是入口函数）\n`;
    }

    if (callees.length > 0) {
      text += `  调用了以下函数（下游，共 ${callees.length} 处）:\n`;
      for (const c of callees.slice(0, 10)) {
        text += `    - ${c.callee} (行 ${c.line})\n`;
      }
      if (callees.length > 10) text += `    ... 共 ${callees.length} 处\n`;
    } else {
      text += `  调用了以下函数（下游）: 无（叶子函数）\n`;
    }

    return text;
  }

  stats() {
    return { functions: this.nodes.size, calls: this.edges.length };
  }
}

module.exports = { CallGraph };
