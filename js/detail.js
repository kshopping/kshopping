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
   🔥 상세페이지 데이터 불러오기 (품절 대응)
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

  const btnAdd = $("btnAddCart");

  // ==================================================
  // ❌ 일시 품절 처리 (핵심)
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
      addToCart(data.id, data.name, data.price_sale, data.image_url);
      updateCartCount();
      alert("장바구니에 담겼습니다!");
    };
  }

  // 🏠 메인으로
  $("btnGoHome").onclick = () => (location.href = "index.html");
}

/* ===========================================
   🛒 장바구니 저장
=========================================== */
function addToCart(id, name, price, image) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  const found = cart.find((i) => i.id === id);
  if (found) found.qty++;
  else cart.push({ id, name, price, image, qty: 1 });

  localStorage.setItem("cartItems", JSON.stringify(cart));
}

/* ===========================================
   🚀 초기 실행
=========================================== */
updateCartCount();
loadDetail();

