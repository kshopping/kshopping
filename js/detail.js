import { supabase } from "./supabaseClient.js";

function $(id) {
  return document.getElementById(id);
}

/* ===========================================
   🛒 장바구니 카운트 업데이트
=========================================== */
function updateCartCount() {
  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  const count = cart.reduce((sum, item) => sum + item.qty, 0);

  const el = document.getElementById("cartCount");
  if (!el) return;

  el.textContent = count > 0 ? count : "";
  el.classList.add("pop");

  setTimeout(() => el.classList.remove("pop"), 300);
}

/* ===========================================
   ✅ 유틸
=========================================== */
function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return isNaN(n) ? fallback : n;
}

function formatWon(n) {
  if (n === null || n === undefined || isNaN(n)) return "-";
  return Number(n).toLocaleString("ko-KR") + "원";
}

/* ===========================================
   ✅ 컴퓨터(노트북) 제외 판별
   - category / name 기준
=========================================== */
function isComputerProduct(product) {
  const excludeCategories = ["노트북", "컴퓨터", "데스크탑", "전자기기", "PC"];
  const excludeKeywords = [
    "노트북", "laptop", "notebook", "macbook",
    "hp", "lenovo", "asus", "dell", "msi", "acer",
    "ssd", "ram", "cpu", "i5", "i7", "i9", "ryzen",
    "그래픽", "gpu", "rtx", "gtx"
  ];

  const cat = (product?.category || "").toLowerCase();
  const name = (product?.name || "").toLowerCase();

  const matchCategory = excludeCategories.some(c => cat.includes(c.toLowerCase()));
  const matchKeyword = excludeKeywords.some(k => name.includes(k.toLowerCase()));

  return matchCategory || matchKeyword;
}

/* ===========================================
   ✅ 묶음가격 공식 계산 (고니 규칙 반영)
   1~3개: 비율 적용
   4개 이상: (3개-2개) 차액만큼 일률 증가
=========================================== */
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

  // ✅ 4개 이상: (3개-2개) 차액만큼 일률 증가
  const diff = price3 - price2;
  return price3 + (q - 3) * diff;
}

/* ===========================================
   ✅ 최종가격 계산(컴퓨터 제외)
=========================================== */
function getFinalItemPrice(product, qty) {
  const unitPrice = safeNumber(product?.price_sale ?? 0, 0);
  const q = Math.max(1, safeNumber(qty, 1));

  // 컴퓨터/노트북이면 기본 단가×수량
  if (isComputerProduct(product)) {
    return Math.round(unitPrice * q);
  }

  // 그 외는 묶음가격
  return calcBundlePrice(unitPrice, q);
}

/* ===========================================
   🛒 장바구니 저장 (묶음가격 반영)
=========================================== */
function addToCart(product, qty) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  const unitPrice = safeNumber(product.price_sale, 0);
  const q = Math.max(1, safeNumber(qty, 1));
  const finalPrice = getFinalItemPrice(product, q);

  const found = cart.find((i) => String(i.id) === String(product.id));
  if (found) {
    const newQty = found.qty + q;
    found.qty = newQty;
    found.unitPrice = unitPrice;
    found.bundleApplied = !isComputerProduct(product);
    found.totalPrice = getFinalItemPrice(product, newQty);
    found.updatedAt = Date.now();
  } else {
    cart.push({
      id: product.id,
      name: product.name,
      image: product.image_url,
      qty: q,
      unitPrice: unitPrice,                 // ✅ 단품 세일가
      totalPrice: finalPrice,               // ✅ 묶음 반영 총액
      bundleApplied: !isComputerProduct(product),
      category: product.category || "",
      updatedAt: Date.now()
    });
  }

  localStorage.setItem("cartItems", JSON.stringify(cart));
}

/* ===========================================
   🔥 상세페이지 데이터 불러오기 (품절 대응 + 묶음가격)
=========================================== */
async function loadDetail() {
  const params = new URLSearchParams(location.search);
  const id = params.get("id");

  if (!id) {
    alert("잘못된 접근입니다.");
    location.href = "index.html";
    return;
  }

  // 🎯 Supabase에서 상품 데이터 가져오기
  const { data, error } = await supabase
    .from("products")
    .select("*")
    .eq("id", id)
    .single();

  if (error || !data) {
    alert("상품 정보를 불러올 수 없습니다.");
    return;
  }

  // 🎯 기본 정보 표시
  $("productImage").src = data.image_url;
  $("productName").textContent = data.name;
  $("productDesc").textContent = data.desc ?? "";

  $("productOriginal").textContent =
    `정상가 ${Number(data.price_original).toLocaleString()}원`;

  $("productSale").textContent =
    `파격 세일가 ${Number(data.price_sale).toLocaleString()}원`;

  // 🎯 상세 이미지
  const detailImg = $("detailImage");
  if (data.detail_image_url) {
    detailImg.src = data.detail_image_url;
    detailImg.style.display = "block";
  } else {
    detailImg.style.display = "none";
  }

  // ✅ 수량 UI 연결
  const qtyInput = $("qtyInput");
  const btnMinus = $("btnQtyMinus");
  const btnPlus = $("btnQtyPlus");
  const calcPriceText = $("calcPriceText");
  const bundleHint = $("bundleHint");
  const tierTable = $("tierTable");
  const tier1 = $("tier1");
  const tier2 = $("tier2");
  const tier3 = $("tier3");

  function updatePriceUI() {
    if (!qtyInput || !calcPriceText) return;

    let qty = Math.max(1, safeNumber(qtyInput.value, 1));
    qtyInput.value = qty;

    const unitPrice = safeNumber(data.price_sale, 0);
    const isComputer = isComputerProduct(data);

    if (bundleHint) {
      if (isComputer) {
        bundleHint.textContent = "※ 컴퓨터/노트북 상품은 묶음가격이 적용되지 않습니다.";
      } else {
        bundleHint.textContent = "✅ 묶음가격 자동 적용 (2개/3개 할인). 4개 이상은 동일 증가 규칙 적용";
      }
    }

    if (tierTable && tier1 && tier2 && tier3) {
      if (isComputer) {
        tierTable.style.display = "none";
      } else {
        tierTable.style.display = "block";
        tier1.textContent = `1개: ${formatWon(calcBundlePrice(unitPrice, 1))}`;
        tier2.textContent = `2개: ${formatWon(calcBundlePrice(unitPrice, 2))}`;
        tier3.textContent = `3개: ${formatWon(calcBundlePrice(unitPrice, 3))}`;
      }
    }

    const finalPrice = getFinalItemPrice(data, qty);
    calcPriceText.textContent = formatWon(finalPrice);
  }

  if (qtyInput && calcPriceText) {
    qtyInput.value = 1;
    updatePriceUI();

    btnMinus?.addEventListener("click", () => {
      qtyInput.value = Math.max(1, safeNumber(qtyInput.value, 1) - 1);
      updatePriceUI();
    });

    btnPlus?.addEventListener("click", () => {
      qtyInput.value = Math.max(1, safeNumber(qtyInput.value, 1) + 1);
      updatePriceUI();
    });

    qtyInput.addEventListener("input", () => {
      if (safeNumber(qtyInput.value, 1) < 1) qtyInput.value = 1;
      updatePriceUI();
    });
  }

  const btnAdd = $("btnAddCart");

  // ==================================================
  // ❌ 일시 품절 처리
  // ==================================================
  if (data.sold_out === true) {
    btnAdd.textContent = "일시 품절";
    btnAdd.disabled = true;
    btnAdd.classList.add("sold-out-btn");

    btnAdd.onclick = () => {
      alert("❌ 현재 일시 품절된 상품입니다.");
    };
  } 
  // ==================================================
  // ✅ 정상 상품
  // ==================================================
  else {
    btnAdd.disabled = false;
    btnAdd.textContent = "장바구니 담기";

    btnAdd.onclick = () => {
      const qty = qtyInput ? Math.max(1, safeNumber(qtyInput.value, 1)) : 1;

      addToCart(data, qty);
      updateCartCount();
      alert("장바구니에 담겼습니다!");
    };
  }

  // 🏠 메인으로
  $("btnGoHome").onclick = () => (location.href = "index.html");
}

/* ===========================================
   🚀 초기 실행
=========================================== */
updateCartCount();
loadDetail();
