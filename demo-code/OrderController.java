// OrderController.java — 演示用电商订单控制器
// 故意包含多个业务逻辑漏洞（供 AI 漏洞挖掘程序发现）
package com.demo.shop.controller;

import com.demo.shop.model.Order;
import com.demo.shop.service.PaymentService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final PaymentService paymentService;

    public OrderController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    // 漏洞1: IDOR — 按 id 查订单未校验属主，水平越权
    @GetMapping("/{id}")
    public Order getOrder(@PathVariable Long id) {
        return orderRepo.findById(id);
    }

    // 漏洞2: 金额篡改 — amount 直接用，未校验非负/上限
    @PostMapping("/create")
    public Order createOrder(@RequestParam Long userId,
                             @RequestParam double amount,
                             @RequestParam String productId) {
        Order order = new Order();
        order.setUserId(userId);
        order.setAmount(amount);  // 负数金额/超大值未拦截
        order.setProductId(productId);
        order.setStatus("PENDING");
        return orderRepo.save(order);
    }

    // 漏洞3: 状态机绕过 — 未校验当前状态，已取消订单也能发货
    @PostMapping("/{id}/ship")
    public Order shipOrder(@PathVariable Long id) {
        Order order = orderRepo.findById(id);
        // 缺少: if (order.getStatus() != "PAID") throw ...
        order.setStatus("SHIPPED");
        return orderRepo.save(order);
    }

    // 漏洞4: 幂等性缺失 — 支付接口无幂等键，重复请求重复扣款
    @PostMapping("/{id}/pay")
    public String payOrder(@PathVariable Long id, @RequestParam String paymentMethod) {
        Order order = orderRepo.findById(id);
        paymentService.charge(order.getAmount(), paymentMethod);  // 重复调用 = 重复扣款
        order.setStatus("PAID");
        orderRepo.save(order);
        return "success";
    }

    // 漏洞5: 优惠券叠加 — 未限制使用次数，可叠加导致负金额
    @PostMapping("/{id}/applyCoupon")
    public Order applyCoupon(@PathVariable Long id, @RequestParam String couponCode) {
        Order order = orderRepo.findById(id);
        double discount = couponService.getDiscount(couponCode);
        order.setAmount(order.getAmount() - discount);  // 多次调用 = 多次扣减
        return orderRepo.save(order);
    }

    // 漏洞6: SQL 注入 — 拼接查询（高危补充）
    @GetMapping("/search")
    public List<Order> searchOrders(@RequestParam String keyword) {
        String sql = "SELECT * FROM orders WHERE product LIKE '%" + keyword + "%'";
        return jdbcTemplate.query(sql, new OrderRowMapper());
    }
}
