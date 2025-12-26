// /js/order.js
// ✅ 주문페이지 전용 JS (장바구니 → 주문정보 입력 → 주문완료 저장)
// ✅ 웹만 수정 (앱/모바일 영향 없음)

import { supabase } from "./supabaseClient.js";

const submitBtn = document.getElementById("submitOrder");
if (submitBtn) {
  submitBtn.addEventListener("click", handleSubmitOrder);
}

async function handleSubmitOrder(e) {
  if (e) e.preventDefault();

  try {
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
      return;
    }

    // 3) 기본 입력 검증
    if (!name || !phone || !address) {
      alert("⚠️ 이름/연락처/주소는 필수 입력입니다.");
      return;
    }

    // 4) 장바구니 가져오기
    const cartItems = JSON.parse(localStorage.getItem("cartItems") || "[]");
    if (!cartItems.length) {
      alert("⚠️ 장바구니가 비어 있습니다.");
      location.href = "index.html";
      return;
    }

    // 5) 총액 계산
    const total = cartItems.reduce((sum, item) => sum + (Number(item.price || 0) * Number(item.qty || 0)), 0);
    const totalQty = cartItems.reduce((sum, item) => sum + Number(item.qty || 0), 0);

    // ✅ 관리자(admin.js)가 보기 쉬운 구조로 통일 (핵심)
    const orderPayload = {
      name,
      phone,
      address,
      memo: memo || "",
      marketing_agree: marketingAgree,

      items: cartItems,     // jsonb
      total: total,         // 관리자에서 total로 쓰기 쉬움
      total_qty: totalQty,

      status: "주문완료",   // ✅ 관리자 필터 통과
      printed: false
    };

    // ✅ A) Supabase 저장 먼저 시도
    submitBtn.disabled = true;
    submitBtn.textContent = "주문 처리 중...";

    const { data, error } = await supabase
      .from("orders")
      .insert([orderPayload])
      .select("*")
      .single();

    // ✅ B) Supabase 실패 시 localStorage 저장 (주문 흐름 끊기지 않게)
    if (error || !data) {
      console.error("❌ Supabase 주문 저장 실패:", error);

      const fallbackOrder = {
        id: "LOCAL_" + Date.now(),
        ...orderPayload,
        created_at: new Date().toISOString()
      };

      const orderList = JSON.parse(localStorage.getItem("orderList") || "[]");
      orderList.push(fallbackOrder);
      localStorage.setItem("orderList", JSON.stringify(orderList));

      // 장바구니 비우기
      localStorage.removeItem("cartItems");

      // 주문완료 페이지 이동 + lastOrder 저장
      localStorage.setItem("lastOrder", JSON.stringify(fallbackOrder));
      location.href = "order_complete.html";
      return;
    }

    // ✅ Supabase 성공 시
    // 장바구니 비우기
    localStorage.removeItem("cartItems");

    // 주문완료 페이지에서 보여주기용
    localStorage.setItem("lastOrder", JSON.stringify(data));

    // ✅ id를 URL로도 넘김 (새로고침/조회 안정)
    location.href = `order_complete.html?id=${data.id}`;

  } catch (err) {
    console.error("❌ 주문 처리 중 오류:", err);
    alert("⚠️ 주문 처리 중 오류가 발생했습니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
  }
}
