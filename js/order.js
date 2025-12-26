// /js/order.js
// ✅ 주문페이지 전용 JS (장바구니 → 주문정보 입력 → 주문완료 저장)
// ✅ 웹만 수정 (앱/모바일 영향 없음)
// ✅ orders 테이블 id(text) 자동생성이 없으므로 id를 직접 생성하여 저장
// ✅ Supabase 저장 성공시에만 장바구니 삭제 + 완료페이지 이동 (주문 누락 방지)

import { supabase } from "./supabaseClient.js";

const submitBtn = document.getElementById("submitOrder");
if (submitBtn) {
  submitBtn.addEventListener("click", handleSubmitOrder);
}

async function handleSubmitOrder(e) {
  if (e) e.preventDefault();

  // 버튼 잠금
  submitBtn.disabled = true;
  submitBtn.textContent = "주문 저장 중...";

  // 1) 입력값 가져오기
  const name = document.getElementById("name")?.value.trim();
  const phone = document.getElementById("phone")?.value.trim();
  const address = document.getElementById("address")?.value.trim();
  const memo = document.getElementById("memo")?.value.trim();
  const marketingAgree = document.getElementById("agree_marketing")?.checked || false;

  // 2) 필수 동의 체크
  const agreeRequired = document.getElementById("agree_required");
  if (!agreeRequired?.checked) {
    alert("⚠️ [필수] 개인정보 수집 및 이용 동의가 필요합니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    return;
  }

  // 3) 기본 입력 검증
  if (!name || !phone || !address) {
    alert("⚠️ 이름/연락처/주소는 필수 입력입니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    return;
  }

  // 4) 장바구니 가져오기
  const cartItems = JSON.parse(localStorage.getItem("cartItems") || "[]");
  if (!cartItems.length) {
    alert("⚠️ 장바구니가 비어 있습니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    location.href = "index.html";
    return;
  }

  // 5) 총액/수량 계산
  const total = cartItems.reduce(
    (sum, item) => sum + (Number(item.price || 0) * Number(item.qty || 0)),
    0
  );
  const totalQty = cartItems.reduce((sum, item) => sum + Number(item.qty || 0), 0);

  // ✅ 핵심: id 직접 생성 (orders.id가 text이고 자동생성 없음)
  const orderId = "ORDER_" + Date.now();
  const createdAt = new Date().toISOString();

  // 6) 주문 데이터 생성 (Supabase 컬럼 구조에 정확히 맞춤)
  const orderPayload = {
    id: orderId,                 // ✅ 필수
    created_at: createdAt,       // ✅ created_at은 default now() 있어도 명시하면 안전
    name,
    phone,
    address,
    memo: memo || "",
    items: cartItems,

    // ✅ 관리자 주문관리에서 사용
    total: total,
    total_qty: totalQty,
    marketing_agree: marketingAgree,
    status: "결제대기",

    // ✅ 관리자에서 eq("printed", false)로 불러오므로 필수
    printed: false,
  };

  try {
    // ✅ Supabase 저장
    const { data, error } = await supabase
      .from("orders")
      .insert([orderPayload])
      .select("*")
      .single();

    if (error || !data) {
      console.error("❌ Supabase 주문 저장 실패:", error);

      alert(
        "❌ 주문 저장에 실패했습니다.\n\n" +
        "주문이 관리자 주문관리로 들어오지 않았습니다.\n" +
        "장바구니는 그대로 유지됩니다.\n\n" +
        "잠시 후 다시 시도해주세요."
      );

      submitBtn.disabled = false;
      submitBtn.textContent = "주문하기";
      return;
    }

    // ✅ 성공했을 때만 장바구니 삭제 + 완료 이동
    localStorage.removeItem("cartItems");
    localStorage.setItem("lastOrder", JSON.stringify(data));

    location.href = `order_complete.html?id=${data.id}`;

  } catch (err) {
    console.error("❌ Supabase 주문 저장 예외:", err);

    alert(
      "❌ 주문 저장 중 오류가 발생했습니다.\n\n" +
      "주문이 관리자 주문관리로 들어오지 않았습니다.\n" +
      "장바구니는 그대로 유지됩니다.\n\n" +
      "잠시 후 다시 시도해주세요."
    );

    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    return;
  }
}

