/* ===========================================================
   ✅ 유틸
=========================================================== */
function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return isNaN(n) ? fallback : n;
}

function formatWon(n) {
  if (n === null || n === undefined || isNaN(n)) return "-";
  return Number(n).toLocaleString("ko-KR") + "원";
}

/* ===========================================================
   ✅ 컴퓨터(노트북) 제외 판별 (cartItem 기준)
=========================================================== */
function isComputerItem(item) {
  const excludeCategories = ["노트북", "컴퓨터", "데스크탑", "전자기기", "PC"];
  const excludeKeywords = [
    "노트북", "laptop", "notebook", "macbook",
    "hp", "lenovo", "asus", "dell", "msi", "acer",
    "ssd", "ram", "cpu", "i5", "i7", "i9", "ryzen",
    "그래픽", "gpu", "rtx", "gtx"
  ];

  const cat = (item?.category || "").toLowerCase();
  const name = (item?.name || "").toLowerCase();

  const matchCategory = excludeCategories.some(c => cat.includes(c.toLowerCase()));
  const matchKeyword = excludeKeywords.some(k => name.includes(k.toLowerCase()));

  return matchCategory || matchKeyword;
}

/* ===========================================================
   ✅ 묶음가격 공식 계산 (고니 규칙 반영)
   1~3개: 비율 적용
   4개 이상: (3개-2개) 차액만큼 일률 증가
=========================================================== */
function calcBundlePrice(unitPrice, qty) {
  const ratio2 = 19900 / 13900;
  const ratio3 = 26900 / 13900;

  const u = safeNumber(unitPrice, 0);
  const q = Math.max(1, safeNumber(qty, 1));

  const price1 = Math.round(u);
  const price2 = Math.round(u * ratio2);
  const price3 = Math.round(u * ratio3);

  if (q === 1) return price1;
  if (q === 2) return price2;
  if (q === 3) return price3;

  const diff = price3 - price2;
  return price3 + (q - 3) * diff;
}

/* ===========================================================
   ✅ 아이템 totalPrice 재계산
=========================================================== */
function recalcItemTotal(item) {
  const unitPrice = safeNumber(item.unitPrice ?? item.price ?? 0, 0);
  const qty = Math.max(1, safeNumber(item.qty ?? 1, 1));

  item.unitPrice = unitPrice;
  item.qty = qty;

  if (isComputerItem(item)) {
    item.bundleApplied = false;
    item.totalPrice = Math.round(unitPrice * qty);
  } else {
    item.bundleApplied = true;
    item.totalPrice = calcBundlePrice(unitPrice, qty);
  }
}

/* ===========================================================
   🛒 장바구니 로드 + 자동 보정
=========================================================== */
function getCart() {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  cart.forEach(item => {
    if (item.unitPrice === undefined) item.unitPrice = safeNumber(item.price ?? 0, 0);
    if (item.qty === undefined) item.qty = 1;
    recalcItemTotal(item);
  });

  localStorage.setItem("cartItems", JSON.stringify(cart));
  return cart;
}

/* ===========================================================
   🛒 장바구니 렌더
=========================================================== */
function loadCart() {
  const cart = getCart();
  const listArea = document.getElementById("cartList");
  const totalArea = document.getElementById("cartTotal");

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
    const itemTotal = safeNumber(item.totalPrice ?? 0, 0);
    totalPrice += itemTotal;

    const unitText = `단품 ${formatWon(item.unitPrice)}`;
    const bundleText = isComputerItem(item) ? " (묶음 제외)" : " (묶음 적용)";
    const currentSumText = `현재 합계: <b>${formatWon(itemTotal)}</b>`;

    html += `
      <div class="cart-item-box">
        <img src="${item.image}" alt="${item.name}">

        <div style="flex:1;">
          <div class="cart-name">${item.name}</div>
          <div class="cart-price">
            ${unitText}${bundleText}<br>
            ${currentSumText}
          </div>

          <div class="qty-box">
            <button class="qty-btn" onclick="changeQty(${index}, -1)">-</button>
            <span style="min-width:20px; display:inline-block; text-align:center; font-weight:700;">${item.qty}</span>
            <button class="qty-btn" onclick="changeQty(${index}, 1)">+</button>
          </div>
        </div>

        <button class="remove-btn" onclick="removeItem(${index})">삭제</button>
      </div>
    `;
  });

  listArea.innerHTML = html;

  const totalQty = cart.reduce((t, i) => t + safeNumber(i.qty, 0), 0);

  totalArea.innerHTML = `
    총 수량: ${totalQty}개<br>
    총 금액: ${formatWon(totalPrice)}
  `;
}

/* ===========================================================
   🔼 수량 증가/감소
=========================================================== */
window.changeQty = function (index, diff) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  if (!cart[index]) return;

  cart[index].qty = Math.max(1, safeNumber(cart[index].qty, 1) + diff);

  recalcItemTotal(cart[index]);

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

  cart.forEach(item => {
    if (item.unitPrice === undefined) item.unitPrice = safeNumber(item.price ?? 0, 0);
    if (item.qty === undefined) item.qty = 1;
    recalcItemTotal(item);
  });
  localStorage.setItem("cartItems", JSON.stringify(cart));

  location.href = "order.html";
});

/* ===========================================================
   🚀 초기 실행
=========================================================== */
loadCart();

/* ===========================================================
   🔹 빈 장바구니일 때 메인으로 돌아가기 버튼 생성
=========================================================== */
(function addBackButtonWhenEmpty() {
  const wrap = document.getElementById("cart-wrap");
  if (!wrap) return;

  const observer = new MutationObserver(() => {
    const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

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
