// src/components/CodeBlock.jsx — 代码块（highlight.js 高亮 + 复制按钮）
import { useEffect, useRef, useState } from "react";
import hljs from "highlight.js/lib/core";
import javascript from "highlight.js/lib/languages/javascript";
import java from "highlight.js/lib/languages/java";
import python from "highlight.js/lib/languages/python";
import go from "highlight.js/lib/languages/go";
import json from "highlight.js/lib/languages/json";
import bash from "highlight.js/lib/languages/bash";
import "highlight.js/styles/github-dark.css";

// 只注册用到的语言，减小体积
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("java", java);
hljs.registerLanguage("python", python);
hljs.registerLanguage("go", go);
hljs.registerLanguage("json", json);
hljs.registerLanguage("bash", bash);
// 兜底
const LANG_FALLBACK = "javascript";

export default function CodeBlock({ code, language = "javascript", showCopy = true }) {
  const codeRef = useRef(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (codeRef.current) {
      // 重置避免重复高亮残留
      codeRef.current.removeAttribute("data-highlighted");
      codeRef.current.textContent = code;
      try {
        hljs.highlightElement(codeRef.current);
      } catch {
        /* 语言未注册，保持纯文本 */
      }
    }
  }, [code, language]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* 忽略 */
    }
  };

  const lang = hljs.getLanguage(language) ? language : LANG_FALLBACK;

  return (
    <div style={{ position: "relative" }}>
      {showCopy && (
        <button
          onClick={copy}
          className="secondary"
          style={{ position: "absolute", top: 8, right: 8, padding: "4px 10px", fontSize: 12, zIndex: 1 }}
        >
          {copied ? "✓ 已复制" : "复制"}
        </button>
      )}
      <pre style={{ margin: 0 }}>
        <code ref={codeRef} className={`language-${lang}`} style={{ background: "transparent", padding: 0 }} />
      </pre>
    </div>
  );
}
