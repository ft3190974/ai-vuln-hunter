// web/server/routes/graph.js — 知识图谱路由（async，用 listNodes/listEdges 替换直接访问）

const express = require("express");

function graphRoutes({ engine }) {
  const router = express.Router();

  router.get("/graph", async (req, res) => {
    try {
      const kg = engine.knowledgeGraph;
      const nodes = (await kg.listNodes()).map((n) => ({
        data: {
          id: n.id,
          label: (n.title || n.id).slice(0, 40),
          categories: n.categories || [],
          fullTitle: n.title || n.id,
          attackPattern: n.attackPattern ? true : false,
        },
      }));
      const edges = (await kg.listEdges()).map((e, i) => ({
        data: { id: `e${i}`, source: e.from, target: e.to, type: e.type },
      }));
      res.json({ nodes, edges, stats: await kg.stats() });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  router.get("/graph/variants/:id", async (req, res) => {
    try {
      const variants = await engine.knowledgeGraph.findVariants(req.params.id);
      res.json(variants);
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  });

  return router;
}

module.exports = graphRoutes;
