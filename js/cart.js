import { supabase } from "./supabaseClient.js";

/* ===========================================================
   ✅ 100원 단위 무조건 올림 (확정값)
=========================================================== */
function ceil100(price) {
  return Math.ceil(Number(price || 0) / 100) * 100;
}

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
   ✅ cartItem에서 productId 추출 (여러 형태 대응)
   - item.productId / item.product_id / item.id / item.pid 등
=========================================================== */
function getItemProductId(item) {
  return (
    item?.productId ??
    item?.product_id ??
    item?.pid ??
    item?.id ??
    item?.productIdStr ??
    null
  );
}

/* ===========================================================
   ✅ products 테이블에서 bundle_enabled 상태를 받아서
   cartItems에 주입 (핵심)
=========================================================== */
let _bundleMapCache = null;
let _bundleMapCacheTime = 0;

async function getProductBundleMap() {
  // ✅ 30초 캐시
  const now = Date.now();
  if (_bundleMapCache && (now - _bundleMapCacheTime) < 30000) {
    return _bundleMapCache;
  }

  const { data: products, error } = await supabase
    .from("products")
    .select("id, bundle_enabled");

  if (error) {
    console.error("getProductBundleMap error:", error);
    return {};
  }

  const map = {};
  (products ?? []).forEach(p => {
    map[String(p.id)] = (p.bundle_enabled !== false);
  });

  _bundleMapCache = map;
  _bundleMapCacheTime = now;
  return map;
}

async function applyBundleEnabledToCartItems(cart) {
  const map = await getProductBundleMap();
  const items = (cart ?? []).map(it => ({ ...it }));

  items.forEach(it => {
    const pid = getItemProductId(it);
    if (!pid) return;

    // ✅ DB 기준 bundle_enabled 주입
    const on = map[String(pid)];
    if (on === false) it.bundle_enabled = false;
    if (on === true) it.bundle_enabled = true;
  });

  return items;
}

/* ===========================================================
   🛒 헤더 장바구니 아이콘 아래 총액 업데이트
=========================================================== */
function updateCartTotalBadge() {
  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  const total = cart.reduce((sum, item) => sum + (Number(item.totalPrice) || 0), 0);

  const el = document.getElementById("cartTotal");
  if (!el) return;

  el.textContent = total > 0 ? formatWon(total) : "";
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
   ✅ 묶음 적용 가능 여부 판별 (최종 규칙)
   - 컴퓨터/노트북이면 무조건 제외
   - bundle_enabled === false 면 제외
=========================================================== */
function isBundleEnabledItem(item) {
  if (isComputerItem(item)) return false;
  if (item?.bundle_enabled === false) return false;
  return true;
}

/* ===========================================================
   ✅ 묶음가격 공식 계산 (고니 규칙 반영)
=========================================================== */
function calcBundlePrice(unitPrice, qty) {
  const ratio2 = 19900 / 13900;
  const ratio3 = 26900 / 13900;

  const u = safeNumber(unitPrice, 0);
  const q = Math.max(1, safeNumber(qty, 1));

  const price1 = Math.round(u);
  const price2 = Math.round(u * ratio2);
  const price3 = Math.round(u * ratio3);

  let result = 0;

  if (q === 1) result = price1;
  else if (q === 2) result = price2;
  else if (q === 3) result = price3;
  else {
    const diff = price3 - price2;
    result = price3 + (q - 3) * diff;
  }

  return ceil100(result);
}

/* ===========================================================
   ✅ 아이템 totalPrice 재계산 (무조건 ceil100 확정값)
=========================================================== */
function recalcItemTotal(item) {
  const unitPrice = safeNumber(item.unitPrice ?? item.price ?? 0, 0);
  const qty = Math.max(1, safeNumber(item.qty ?? 1, 1));

  item.unitPrice = unitPrice;
  item.qty = qty;

  const bundleOk = isBundleEnabledItem(item);

  if (!bundleOk) {
    item.bundleApplied = false;
    item.totalPrice = ceil100(Math.round(unitPrice * qty));
  } else {
    item.bundleApplied = true;
    item.totalPrice = calcBundlePrice(unitPrice, qty);
  }

  item.totalPrice = ceil100(item.totalPrice);
}

/* ===========================================================
   🛒 장바구니 로드 + DB 반영 + 자동 보정 (핵심)
=========================================================== */
async function getCart() {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  // ✅ DB에서 bundle_enabled 주입
  cart = await applyBundleEnabledToCartItems(cart);

  cart.forEach(item => {
    if (item.unitPrice === undefined) item.unitPrice = safeNumber(item.price ?? 0, 0);
    if (item.qty === undefined) item.qty = 1;

    // ✅ bundle_enabled가 DB에서도 못 찾으면 true fallback
    if (item.bundle_enabled === undefined || item.bundle_enabled === null) {
      item.bundle_enabled = true;
    }

    recalcItemTotal(item);
  });

  localStorage.setItem("cartItems", JSON.stringify(cart));
  return cart;
}

/* ===========================================================
   🛒 장바구니 렌더
=========================================================== */
async function loadCart() {
  const cart = await getCart();
  const listArea = document.getElementById("cartList");
  const totalArea = document.getElementById("cartTotal");

  // ✅ 헤더 총액 배지 업데이트
  updateCartTotalBadge();

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

    // ✅ 문구 단순화: 2종만 표시
    const bundleOk = isBundleEnabledItem(item);
    const bundleText = bundleOk ? " (묶음 적용 ✅)" : " (묶음 제외 ❌)";

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
window.changeQty = async function (index, diff) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  if (!cart[index]) return;

  // ✅ DB 반영
  cart = await applyBundleEnabledToCartItems(cart);

  cart[index].qty = Math.max(1, safeNumber(cart[index].qty, 1) + diff);
  recalcItemTotal(cart[index]);

  localStorage.setItem("cartItems", JSON.stringify(cart));

  await loadCart();

  // ✅ 헤더 카운트/총액 같이 갱신
  if (window.updateCartCount) updateCartCount();
  updateCartTotalBadge();

  if (window.updateCartPreview) updateCartPreview();
};

/* ===========================================================
   ❌ 삭제
=========================================================== */
window.removeItem = async function (index) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  cart.splice(index, 1);
  localStorage.setItem("cartItems", JSON.stringify(cart));

  await loadCart();

  // ✅ 헤더 카운트/총액 같이 갱신
  if (window.updateCartCount) updateCartCount();
  updateCartTotalBadge();

  if (window.updateCartPreview) updateCartPreview();
};

/* ===========================================================
   🧾 주문 페이지 이동
=========================================================== */
document.getElementById("goOrder").addEventListener("click", async () => {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  if (cart.length === 0) {
    alert("장바구니가 비어 있습니다.");
    return;
  }

  cart = await applyBundleEnabledToCartItems(cart);

  cart.forEach(item => {
    if (item.unitPrice === undefined) item.unitPrice = safeNumber(item.price ?? 0, 0);
    if (item.qty === undefined) item.qty = 1;

    // ✅ bundle_enabled fallback
    if (item.bundle_enabled === undefined || item.bundle_enabled === null) {
      item.bundle_enabled = true;
    }

    recalcItemTotal(item);
  });

  // ✅ 최종 확정값 저장
  localStorage.setItem("cartItems", JSON.stringify(cart));

  // ✅ 배지도 업데이트하고 이동
  updateCartTotalBadge();

  location.href = "order.html";
});

/* ===========================================================
   🚀 초기 실행 (async)
=========================================================== */
(async function initCart() {
  await loadCart();
})();

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
