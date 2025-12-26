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

  // 1) 입력값 가져오기
  const name = document.getElementById("name")?.value.trim();
  const phone = document.getElementById("phone")?.value.trim();
  const address = document.getElementById("address")?.value.trim();
  const memo = document.getElementById("memo")?.value.trim();

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
  const total = cartItems.reduce(
    (sum, item) => sum + (Number(item.price || 0) * Number(item.qty || 0)),
    0
  );
  const totalQty = cartItems.reduce((sum, item) => sum + Number(item.qty || 0), 0);

  // 6) 주문 데이터 생성 (Supabase용)
  // ✅ admin.js가 쓰는 구조에 맞춤 + printed:false 반드시 저장
  const orderPayload = {
    name,
    phone,
    address,
    memo: memo || "",
    marketing_agree: document.getElementById("agree_marketing")?.checked || false,

    items: cartItems,          // jsonb
    total: total,              // admin.js에서 금액 표시용
    total_qty: totalQty,       // admin.js에서 수량 표시용

    status: "결제대기",

    // ✅ 이게 핵심: 관리자 주문관리에서 eq("printed", false)로 불러오므로 반드시 false
    printed: false,
  };

  // ✅ A) Supabase 저장 먼저 시도
  let supabaseSaved = false;
  let savedOrderData = null;

  try {
    const { data, error } = await supabase
      .from("orders")
      .insert([orderPayload])
      .select("*")
      .single();

    if (error) {
      console.error("❌ Supabase 주문 저장 실패:", error);
      supabaseSaved = false;
    } else {
      supabaseSaved = true;
      savedOrderData = data;
    }
  } catch (err) {
    console.error("❌ Supabase 주문 저장 예외:", err);
    supabaseSaved = false;
  }

  // ✅ B) Supabase 실패해도 localStorage 저장은 무조건 수행 (주문 흐름 끊기지 않게)
  if (!supabaseSaved) {
    const fallbackOrder = {
      id: "LOCAL_" + Date.now(),
      created_at: new Date().toISOString(),
      ...orderPayload,
    };

    const orderList = JSON.parse(localStorage.getItem("orderList") || "[]");
    orderList.push(fallbackOrder);
    localStorage.setItem("orderList", JSON.stringify(orderList));

    // 장바구니 비우기
    localStorage.removeItem("cartItems");

    // 주문완료 페이지로 이동
    localStorage.setItem("lastOrder", JSON.stringify(fallbackOrder));
    location.href = "order_complete.html";
    return;
  }

  // ✅ Supabase 성공 시
  localStorage.removeItem("cartItems");
  localStorage.setItem("lastOrder", JSON.stringify(savedOrderData));

  // ✅ id를 URL로도 넘김(안정)
  location.href = `order_complete.html?id=${savedOrderData.id}`;
}
