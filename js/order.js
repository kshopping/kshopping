// /js/order.js
// ✅ 주문페이지 전용 JS (장바구니 → 주문정보 입력 → 주문완료 저장)

const submitBtn = document.getElementById("submitOrder");
if (submitBtn) {
  submitBtn.addEventListener("click", handleSubmitOrder);
}

// ✅ 주문하기 버튼 클릭 처리
function handleSubmitOrder(e) {
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
  const totalPrice = cartItems.reduce((sum, item) => sum + (item.price * item.qty), 0);
  const totalQty = cartItems.reduce((sum, item) => sum + item.qty, 0);

  // 6) 주문 데이터 생성
  const orderData = {
    id: "ORDER_" + Date.now(),
    createdAt: new Date().toISOString(),
    customer: {
      name,
      phone,
      address,
      memo,
      marketingAgree: document.getElementById("agree_marketing")?.checked || false,
    },
    items: cartItems,
    totalQty,
    totalPrice,
    status: "결제대기",
  };

  // 7) 주문 저장
  const orderList = JSON.parse(localStorage.getItem("orderList") || "[]");
  orderList.push(orderData);
  localStorage.setItem("orderList", JSON.stringify(orderList));

  // 8) 장바구니 비우기
  localStorage.removeItem("cartItems");

  // 9) 주문완료 페이지 이동
  localStorage.setItem("lastOrder", JSON.stringify(orderData));
  location.href = "order_complete.html";
}
