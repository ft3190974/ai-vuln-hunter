// src/hooks/useSessionState.js
// 带 sessionStorage 持久化的 useState —— 组件卸载（如切换路由）后再挂载，
// 自动恢复上次的值。用于扫描页防止切换导航后任务/上传状态丢失。
//
// 用法：const [job, setJob] = useSessionState("scan:job", null);
// 注意：value 必须可 JSON 序列化。tab 关闭后 sessionStorage 自动清空（符合预期）。

import { useState, useEffect } from "react";

const PREFIX = "avh:";

export function useSessionState(key, defaultValue) {
  const fullKey = PREFIX + key;
  const [value, setValue] = useState(() => {
    try {
      const raw = sessionStorage.getItem(fullKey);
      if (raw !== null) return JSON.parse(raw);
    } catch {}
    return typeof defaultValue === "function" ? defaultValue() : defaultValue;
  });

  // 值变化时写回 sessionStorage（跳过 undefined）
  useEffect(() => {
    try {
      if (value === undefined) return;
      sessionStorage.setItem(fullKey, JSON.stringify(value));
    } catch {}
  }, [fullKey, value]);

  return [value, setValue];
}

// 清除本模块管理的所有扫描会话状态（扫描完成/失败后调用）
export function clearScanSession() {
  try {
    const keys = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k && k.startsWith(PREFIX + "scan:")) keys.push(k);
    }
    keys.forEach((k) => sessionStorage.removeItem(k));
  } catch {}
}
