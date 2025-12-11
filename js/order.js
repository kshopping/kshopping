import { supabase } from "./supabaseClient.js";

const $ = (id) => document.getElementById(id);

/* ===========================================================
   🔥 주문번호 생성
=========================================================== */
function generateOrderId() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  const rand = Math.floor(Math.random() * 9000 + 1000);
  return `KS-${y}${m}${d}-${rand}`;
}

/* ===========================================================
   🔥 입력값 검증 함수
=========================================================== */
function validateInput(name, phone, address) {
  if (!name) return "이름을 입력하세요.";
  if (!phone) return "연락처를 입력하세요.";
  if (!address) return "주소를 입력하세요.";

  // 전화번호 기본 검증
  const phoneReg = /^[0-9\-]+$/;
  if (!phoneReg.test(phone)) {
    return "연락처는 숫자와 하이폰만 입력 가능합니다.";
  }

  if (address.length < 5) {
    return "주소가 너무 짧습니다.";
  }

  return null;
}

/* ===========================================================
   🧾 주문 저장
=========================================================== */
$("submitOrder").addEventListener("click", async () => {

  const btn = $("submitOrder");
  btn.disabled = true;
  btn.textContent = "주문 처리중...";

  const name = $("name").value.trim();
  const phone = $("phone").value.trim();
  const address = $("address").value.trim();
  const memo = $("memo").value.trim();

  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  /* ===== 입력 검증 ===== */
  const errorMsg = validateInput(name, phone, address);
  if (errorMsg) {
    alert(errorMsg);
    btn.disabled = false;
    btn.textContent = "✔ 주문하기";
    return;
  }

  if (cart.length === 0) {
    alert("장바구니가 비어 있습니다.");
    btn.disabled = false;
    btn.textContent = "✔ 주문하기";
    return;
  }

  /* ===== 총 금액 & 총 수량 계산 ===== */
  const total = cart.reduce((s, i) => s + i.price * i.qty, 0);
  const totalQty = cart.reduce((s, i) => s + i.qty, 0);

  /* ===== 주문 데이터 생성 ===== */
  const orderId = generateOrderId();

  const { error } = await supabase.from("orders").insert({
    id: orderId,
    name,
    phone,
    address,
    memo,
    items: cart,
    total,
    total_qty: totalQty,
    created_at: new Date().toISOString()
  });

  if (error) {
    console.error(error);
    alert("주문 저장 중 오류가 발생했습니다.");
    btn.disabled = false;
    btn.textContent = "✔ 주문하기";
    return;
  }

  /* ===== 주문 완료 처리 ===== */
  localStorage.removeItem("cartItems");
  location.href = `order_complete.html?id=${orderId}`;
});
