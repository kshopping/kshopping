/* ===========================================================
   🛒 장바구니 로드
=========================================================== */
function loadCart() {
  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  const listArea = document.getElementById("cartList");
  const totalArea = document.getElementById("cartTotal");

  // 장바구니 비었을 때
  if (cart.length === 0) {
    listArea.innerHTML = `
      <div style="text-align:center; padding:40px 0; color:#666; font-size:18px;">
        🛒 장바구니가 비어 있습니다.
      </div>
    `;
    totalArea.innerHTML = "";
    return;
  }

  let html = "";
  let totalPrice = 0;

  cart.forEach((item, index) => {
    const itemTotal = item.price * item.qty;
    totalPrice += itemTotal;

    html += `
      <div class="cart-item-box">
        <img src="${item.image}" alt="${item.name}">

        <div style="flex:1;">
          <div class="cart-name">${item.name}</div>
          <div class="cart-price">${item.price.toLocaleString()}원</div>

          <div class="qty-box">
            <button class="qty-btn" onclick="changeQty(${index}, -1)">-</button>
            <span>${item.qty}</span>
            <button class="qty-btn" onclick="changeQty(${index}, 1)">+</button>
          </div>
        </div>

        <button class="remove-btn" onclick="removeItem(${index})">삭제</button>
      </div>
    `;
  });

  listArea.innerHTML = html;

  totalArea.innerHTML = `
    총 수량: ${cart.reduce((t,i)=>t+i.qty,0)}개<br>
    총 금액: ${totalPrice.toLocaleString()}원
  `;
}

/* ===========================================================
   🔼 수량 증가/감소
=========================================================== */
window.changeQty = function (index, diff) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  cart[index].qty += diff;
  if (cart[index].qty < 1) cart[index].qty = 1;

  localStorage.setItem("cartItems", JSON.stringify(cart));

  loadCart();

  if (window.updateCartCount) updateCartCount();
  if (window.updateCartPreview) updateCartPreview();
};

/* ===========================================================
   ❌ 삭제
=========================================================== */
window.removeItem = function (index) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  cart.splice(index, 1);
  localStorage.setItem("cartItems", JSON.stringify(cart));

  loadCart();

  if (window.updateCartCount) updateCartCount();
  if (window.updateCartPreview) updateCartPreview();
};

/* ===========================================================
   🧾 주문 페이지 이동
=========================================================== */
document.getElementById("goOrder").addEventListener("click", () => {
  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  if (cart.length === 0) {
    alert("장바구니가 비어 있습니다.");
    return;
  }

  location.href = "order.html";
});

/* ===========================================================
   🚀 초기 실행
=========================================================== */
loadCart();

/* ===========================================================
   🔹 [추가] 빈 장바구니일 때 메인으로 돌아가기 버튼 생성
   (기존 코드 수정 없음)
=========================================================== */
(function addBackButtonWhenEmpty() {
  const wrap = document.getElementById("cart-wrap");
  if (!wrap) return;

  const observer = new MutationObserver(() => {
    const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

    // 장바구니가 비어 있고, 버튼이 아직 없을 때만
    if (cart.length === 0 && !document.querySelector(".btn-back-main")) {
      const btn = document.createElement("button");
      btn.className = "btn-back-main";
      btn.textContent = "← 메인으로 돌아가기";
      btn.onclick = () => (location.href = "index.html");

      wrap.appendChild(btn);
    }
  });

  observer.observe(wrap, {
    childList: true,
    subtree: true
  });
})();
