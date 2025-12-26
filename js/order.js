// /js/order.js
// ✅ 주문페이지 전용 JS (장바구니 → 주문정보 입력 → 주문완료 저장)
// ✅ Supabase orders 테이블로 저장 (관리자 주문관리와 연동)

import { supabase } from "./supabaseClient.js";

const submitBtn = document.getElementById("submitOrder");
if (submitBtn) {
  submitBtn.addEventListener("click", handleSubmitOrder);
}

// ✅ 주문하기 버튼 클릭 처리
async function handleSubmitOrder(e) {
  if (e) e.preventDefault();

  try {
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

    // 5) 총액/총수량 계산
    const totalPrice = cartItems.reduce(
      (sum, item) => sum + Number(item.price || 0) * Number(item.qty || 0),
      0
    );
    const totalQty = cartItems.reduce((sum, item) => sum + Number(item.qty || 0), 0);

    // 6) 주문 데이터 구성 (관리자(admin.js)에서 사용하는 컬럼명에 맞춤)
    const orderData = {
      name,
      phone,
      address,
      memo: memo || "",
      marketing_agree: document.getElementById("agree_marketing")?.checked || false,
      items: cartItems,
      total: totalPrice,
      total_qty: totalQty,
      status: "결제대기",
      printed: false,
    };

    // 7) Supabase에 주문 저장
    submitBtn.disabled = true;
    submitBtn.textContent = "주문 저장 중...";

    const { data, error } = await supabase
      .from("orders")
      .insert([orderData])
      .select("*")
      .single();

    if (error) {
      console.error(error);
      alert("⚠️ 주문 저장에 실패했습니다. 다시 시도해주세요.");
      submitBtn.disabled = false;
      submitBtn.textContent = "주문하기";
      return;
    }

    // 8) 장바구니 비우기
    localStorage.removeItem("cartItems");

    // 9) 주문완료 페이지 이동 (완료 페이지에서 사용할 수 있도록 lastOrder 저장)
    localStorage.setItem("lastOrder", JSON.stringify(data || orderData));
    location.href = "order_complete.html";
  } catch (err) {
    console.error(err);
    alert("⚠️ 오류가 발생했습니다. 다시 시도해주세요.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
  }
}
