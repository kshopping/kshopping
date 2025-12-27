// /js/order.js
// ✅ 주문페이지 전용 JS (장바구니 → 주문정보 입력 → 주문완료 저장)
// ✅ 묶음가격(totalPrice) 반영 + 컴퓨터(노트북) 제외 규칙 포함
// ✅ orders 테이블 id(text) 자동생성이 없으므로 id를 직접 생성하여 저장
// ✅ Supabase 저장 성공시에만 장바구니 삭제 + 완료페이지 이동 (주문 누락 방지)

import { supabase } from "./supabaseClient.js";

const submitBtn = document.getElementById("submitOrder");
if (submitBtn) {
  submitBtn.addEventListener("click", handleSubmitOrder);
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return isNaN(n) ? fallback : n;
}

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

// ✅ 고니 규칙 적용
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

async function handleSubmitOrder(e) {
  if (e) e.preventDefault();

  submitBtn.disabled = true;
  submitBtn.textContent = "주문 저장 중...";

  const name = document.getElementById("name")?.value.trim();
  const phone = document.getElementById("phone")?.value.trim();
  const address = document.getElementById("address")?.value.trim();
  const memo = document.getElementById("memo")?.value.trim();
  const marketingAgree = document.getElementById("agree_marketing")?.checked || false;

  const agreeRequired = document.getElementById("agree_required");
  if (!agreeRequired?.checked) {
    alert("⚠️ [필수] 개인정보 수집 및 이용 동의가 필요합니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    return;
  }

  if (!name || !phone || !address) {
    alert("⚠️ 이름/연락처/주소는 필수 입력입니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    return;
  }

  const cartItems = JSON.parse(localStorage.getItem("cartItems") || "[]");
  if (!cartItems.length) {
    alert("⚠️ 장바구니가 비어 있습니다.");
    submitBtn.disabled = false;
    submitBtn.textContent = "주문하기";
    location.href = "index.html";
    return;
  }

  // ✅ 주문 직전 보정
  cartItems.forEach(item => {
    if (item.unitPrice === undefined) item.unitPrice = safeNumber(item.price ?? 0, 0);
    if (item.qty === undefined) item.qty = 1;

    if (item.totalPrice === undefined || safeNumber(item.totalPrice, 0) <= 0) {
      recalcItemTotal(item);
    }
  });
  localStorage.setItem("cartItems", JSON.stringify(cartItems));

  // ✅ totalPrice 기준 총액/수량
  const total = cartItems.reduce(
    (sum, item) => sum + safeNumber(item.totalPrice ?? 0, 0),
    0
  );
  const totalQty = cartItems.reduce((sum, item) => sum + safeNumber(item.qty ?? 0, 0), 0);

  const orderId = "ORDER_" + Date.now();
  const createdAt = new Date().toISOString();

  const orderPayload = {
    id: orderId,
    created_at: createdAt,
    name,
    phone,
    address,
    memo: memo || "",
    items: cartItems,
    total: total,
    total_qty: totalQty,
    marketing_agree: marketingAgree,
    status: "결제대기",
    printed: false,
  };

  try {
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

