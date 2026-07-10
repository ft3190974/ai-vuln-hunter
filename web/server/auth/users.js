// auth/users.js — 用户存储（内存版，async 接口；N 完成后可接 Postgres）
//
// 密码用 bcrypt 哈希存储。
// 首个用户自动 admin，其余 member。

const bcrypt = require("bcryptjs");

class UserStore {
  constructor() {
    /** @type {Map<number, object>} */
    this.users = new Map();
    this.counter = 0;
  }

  async create({ username, password }) {
    if (!username || !password) throw new Error("username 和 password 必填");
    if (password.length < 6) throw new Error("密码至少 6 位");
    if (await this.findByUsername(username)) throw new Error("用户名已存在");

    this.counter += 1;
    const id = this.counter;
    const isFirst = id === 1;
    const user = {
      id,
      username,
      passwordHash: await bcrypt.hash(password, 10),
      role: isFirst ? "admin" : "member",
      createdAt: new Date().toISOString(),
    };
    this.users.set(id, user);
    return this._safe(user);
  }

  async findByUsername(username) {
    for (const u of this.users.values()) {
      if (u.username === username) return u;
    }
    return null;
  }

  async findById(id) {
    return this.users.get(id) || null;
  }

  async verifyPassword(username, password) {
    const user = await this.findByUsername(username);
    if (!user) return null;
    const ok = await bcrypt.compare(password, user.passwordHash);
    return ok ? user : null;
  }

  /** 返回不含密码哈希的安全副本 */
  _safe(user) {
    return { id: user.id, username: user.username, role: user.role, createdAt: user.createdAt };
  }

  async count() {
    return this.users.size;
  }
}

module.exports = { UserStore };
