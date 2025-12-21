// /lang/lang.js
// K-SHOPPING 다국어 1단계 (UI 고정 문구 전용)
// ko = 기본 언어 (fallback)
// en = 영어

const LANG = {
  ko: {
    // 공통
    language: "언어",
    home: "홈",
    category: "카테고리",

    // 장바구니 / 주문
    cart: "장바구니",
    add_to_cart: "장바구니 담기",
    buy: "구매하기",
    order: "주문하기",
    order_complete: "주문이 완료되었습니다",

    // 상태
    soldout: "품절",
    selling: "판매중",

    // 메시지
    empty_cart: "장바구니가 비어 있습니다",
    loading: "로딩중입니다",

    // bank-info-box
    foreign_guide: "외국인 전용 구매 안내",
    no_card: "NO CARD REQUIRED",
    no_card_desc: "카드 없이 구매 가능",
    cash_ok: "Cash Transfer OK",
    cash_desc: "입금 확인 후 즉시 배송",
    fast_shipping: "FAST SHIPPING"
  },

  en: {
    // Common
    language: "Language",
    home: "Home",
    category: "Category",

    // Cart / Order
    cart: "Cart",
    add_to_cart: "Add to Cart",
    buy: "Buy Now",
    order: "Place Order",
    order_complete: "Your order has been completed",

    // Status
    soldout: "Sold Out",
    selling: "Available",

    // Messages
    empty_cart: "Your cart is empty",
    loading: "Loading...",

    // bank-info-box
    foreign_guide: "Guide for Foreign Customers",
    no_card: "NO CARD REQUIRED",
    no_card_desc: "Purchase without a credit card",
    cash_ok: "Cash Transfer OK",
    cash_desc: "Shipping after payment confirmation",
    fast_shipping: "FAST SHIPPING"
  }
};

/**
 * 현재 언어를 반환
 * 기본값: ko
 */
function getCurrentLang() {
  return localStorage.getItem("lang") || "ko";
}

/**
 * 언어 적용 (data-lang 기반 텍스트 치환)
 */
function applyLang() {
  const lang = getCurrentLang();

  document.querySelectorAll("[data-lang]").forEach(el => {
    const key = el.dataset.lang;
    if (!key) return;

    el.textContent =
      (LANG[lang] && LANG[lang][key]) ||
      LANG.ko[key] ||
      "";
  });
}

/**
 * 언어 변경
 */
function setLang(lang) {
  if (!LANG[lang]) {
    lang = "ko";
  }
  localStorage.setItem("lang", lang);
  applyLang();
}
// ===============================
// PREPARED LANGUAGES (READY ONLY)
// ===============================

LANG.vi = {
  foreign_guide: "외국인 전용 구매 안내",
  no_card: "NO CARD REQUIRED",
  no_card_desc: "카드 없이 구매 가능",
  cash_ok: "Cash Transfer OK",
  cash_desc: "입금 확인 후 즉시 배송",
  fast_shipping: "FAST SHIPPING"
};

LANG.th = {
  foreign_guide: "외국인 전용 구매 안내",
  no_card: "NO CARD REQUIRED",
  no_card_desc: "카드 없이 구매 가능",
  cash_ok: "Cash Transfer OK",
  cash_desc: "입금 확인 후 즉시 배송",
  fast_shipping: "FAST SHIPPING"
};

LANG.id = {
  foreign_guide: "외국인 전용 구매 안내",
  no_card: "NO CARD REQUIRED",
  no_card_desc: "카드 없이 구매 가능",
  cash_ok: "Cash Transfer OK",
  cash_desc: "입금 확인 후 즉시 배송",
  fast_shipping: "FAST SHIPPING"
};
