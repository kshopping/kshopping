import { supabase } from "./supabaseClient.js";

/* ===========================================================
   🛒 장바구니 이동 버튼 (비어있으면 차단)
=========================================================== */
const cartGoBtn = document.getElementById("cartGoBtn");
if (cartGoBtn) {
  cartGoBtn.addEventListener("click", () => {
    const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

    if (cart.length === 0) {
      alert("장바구니가 비어 있습니다.");
      return;
    }

    location.href = "cart.html";
  });
}

/* ===========================================================
   🛒 장바구니 드롭다운
=========================================================== */
const cartDropdownBtn = document.getElementById("cartDropdownBtn");
const cartPreview = document.getElementById("cart-preview");

if (cartDropdownBtn) {
  cartDropdownBtn.addEventListener("click", () => {
    cartPreview.style.display =
      cartPreview.style.display === "block" ? "none" : "block";
  });
}

/* ===========================================================
   🔥 혼합 슬라이더 (영상 + 이미지 자동전환)
=========================================================== */

let bannerIndex = 0;
let bannerSlides = [];

async function loadBanners() {
  const bannerArea = document.getElementById("banner-area");
  const overlay = document.getElementById("banner-text-overlay");

  if (!bannerArea) return;

  // 기존 배너 요소 삭제
  bannerArea.querySelectorAll("video, img").forEach(el => el.remove());

  bannerIndex = 0;
  bannerSlides = [];

  // Supabase에서 배너 가져오기
  const { data: banners } = await supabase.from("banners").select("*").order("sort_order");

  if (!banners?.length) return;

  banners.forEach((b, i) => {
    let el = null;

    // 🎬 VIDEO
    if (b.video_url && b.video_url !== "EMPTY") {
      el = document.createElement("video");
      el.src = b.video_url;
      el.autoplay = true;
      el.loop = true;
      el.muted = true;
      el.playsInline = true;
    }

    // 🖼 IMAGE
    else if (b.image_url) {
      el = document.createElement("img");
      el.src = b.image_url;
    }

    if (!el) return; // 영상도 이미지도 없으면 skip

    el.classList.add("banner-slide");
    if (i === 0) el.classList.add("active");

    // overlay 바로 밑으로 삽입
    bannerArea.insertBefore(el, overlay);

    bannerSlides.push(el);
  });

  if (bannerSlides.length <= 1) return;

  // 자동 진행
  setInterval(() => {
    bannerSlides[bannerIndex].classList.remove("active");
    bannerIndex = (bannerIndex + 1) % bannerSlides.length;
    bannerSlides[bannerIndex].classList.add("active");
  }, 6000);
}



/* ===========================================================
   🔥 카테고리 로드
=========================================================== */
async function loadCategories() {
  const area = document.getElementById("category-area");
  const { data: categories } = await supabase.from("categories").select("*");

  area.innerHTML = (categories || [])
   .map(c => `<button class="category-btn" data-cat-id="${c.id}">${c.name}</button>`) 
    .join("");
}
 

/* ===========================================================
   🔥 상품 로드 (정상가/세일가 + 가운데 정렬)
=========================================================== */
async function loadProducts(categoryId = null, searchKeyword = null) {
  const area = document.getElementById("product-area");

  let query = supabase.from("products").select("*");
  if (categoryId) query = query.eq("category_id", categoryId);

  const { data: products } = await query;
  if (!products?.length) {
    area.innerHTML = "<p style='padding:20px;'>상품이 없습니다.</p>";
    return;
  }

  let filtered = products;
  if (searchKeyword && searchKeyword.trim() !== "") {
    const keyword = searchKeyword.trim().toLowerCase();
    filtered = products.filter((p) => p.name.toLowerCase().includes(keyword));
  }

  if (!filtered.length) {
    area.innerHTML = "<p style='padding:20px;'>검색 결과가 없습니다.</p>";
    return;
  }

  area.innerHTML = filtered
    .map((p) => {
      const original = Number(p.price_original || 0);
      const sale = Number(p.price_sale || 0);
      const saleRate = original > 0 ? Math.round((1 - sale / original) * 100) : 0;

      return `
        <div class="product-card">

          ${saleRate > 0 ? `<div class="product-badge">-${saleRate}%</div>` : ""}

          <img src="${p.image_url}" alt="${p.name}">

          <div class="product-name">${p.name}</div>
          <div class="product-desc">${p.desc ?? ""}</div>

          <div class="price-box">
            <div class="price-original">정상가 ${original.toLocaleString()}원</div>
            <div class="price-sale">파격 세일가 ${sale.toLocaleString()}원</div>
          </div>

          <div class="product-buttons">
            <button class="btn-add"
              data-id="${p.id}"
              data-name="${encodeURIComponent(p.name)}"
              data-price="${sale}"
              data-image="${encodeURIComponent(p.image_url)}"
            >담기</button>

            <button class="btn-detail" data-id="${p.id}">상세보기</button>
          </div>

        </div>`;
    })
    .join("");
}

/* ===========================================================
   🧲 이벤트 위임 — 담기 & 상세 클릭 정상 작동 핵심
=========================================================== */
document.addEventListener("click", (e) => {

  // 카테고리 버튼
  const catBtn = e.target.closest(".category-btn");
  if (catBtn) {
    document.querySelectorAll(".category-btn").forEach((b) => b.classList.remove("active-cat"));
    catBtn.classList.add("active-cat");
    loadProducts(catBtn.dataset.catId);
    return;
  }

  // 담기 버튼
  const addBtn = e.target.closest(".btn-add");
  if (addBtn) {
    const id = Number(addBtn.dataset.id);
    const name = decodeURIComponent(addBtn.dataset.name);
    const price = Number(addBtn.dataset.price);
    const image = decodeURIComponent(addBtn.dataset.image);

    addToCart(id, name, price, image);
    addBtn.classList.add("btn-glow");
    setTimeout(() => addBtn.classList.remove("btn-glow"), 400);
    return;
  }

  // 상세보기 버튼
  const detailBtn = e.target.closest(".btn-detail");
  if (detailBtn) {
    location.href = `detail.html?id=${detailBtn.dataset.id}`;
  }
});

/* ===========================================================
   🎉 오늘의 특가
=========================================================== */
async function loadTodayDeal() {
  const box = document.getElementById("today-deal");
  if (!box) return;

  const { data: products } = await supabase.from("products").select("*");
  if (!products?.length) return;

  const p = products[Math.floor(Math.random() * products.length)];

  const original = Number(p.price_original || 0);
  const sale = Number(p.price_sale || 0);
  const rate = original ? Math.round((1 - sale / original) * 100) : 0;

  box.innerHTML = `
    🎁 <b>오늘의 특가</b><br>
    ${p.name}<br>
    정상가 ${original.toLocaleString()}원 → 
    <b style="color:red;">파격 세일가 ${sale.toLocaleString()}원</b>
    ${rate ? `<span style="color:#ff4d4f; font-weight:bold;">(-${rate}%)</span>` : ""}
  `;
}

/* ===========================================================
   🛒 장바구니 개수 표시
=========================================================== */
function updateCartCount() {
  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  const count = cart.reduce((sum, item) => sum + item.qty, 0);
  const el = document.getElementById("cartCount");
  if (!el) return;

  el.textContent = count || "";
  el.classList.add("pop");
  setTimeout(() => el.classList.remove("pop"), 300);
}
window.updateCartCount = updateCartCount;

/* ===========================================================
   🛒 장바구니 미리보기
=========================================================== */
function updateCartPreview() {
  const preview = document.getElementById("cart-preview");
  if (!preview) return;

  const cart = JSON.parse(localStorage.getItem("cartItems") || "[]");

  preview.innerHTML =
    cart.length
      ? cart.map(
          (i) => `
        <div class="cart-item">
          <img src="${i.image}">
          <div class="cart-item-name">${i.name}</div>
          <div>x${i.qty}</div>
        </div>`
        ).join("")
      : "<p class='empty-cart'>비어있음</p>";
}
window.updateCartPreview = updateCartPreview;

/* ===========================================================
   🎉 토스트 메시지
=========================================================== */
function showToast(msg) {
  const toast = document.getElementById("toast");
  if (!toast) return;

  toast.textContent = msg;
  toast.style.opacity = 1;

  setTimeout(() => (toast.style.opacity = 0), 1800);
}
window.showToast = showToast;

/* ===========================================================
   🛒 장바구니 담기
=========================================================== */
function addToCart(id, name, price, image) {
  let cart = JSON.parse(localStorage.getItem("cartItems") || "[]");
  const found = cart.find((i) => i.id === id);
  found ? (found.qty += 1) : cart.push({ id, name, price, image, qty: 1 });

  localStorage.setItem("cartItems", JSON.stringify(cart));

  updateCartCount();
  updateCartPreview();
  showToast("🛒 장바구니에 담았습니다!");
}
window.addToCart = addToCart;

/* ===========================================================
   🔥 계좌 정보 로드
=========================================================== */
async function loadBankInfo() {
  const { data } = await supabase.from("account_info").select("*");
  const el = document.getElementById("bankDynamic");

  if (!data?.length) {
    el.textContent = "입금 계좌 정보를 불러올 수 없습니다.";
    return;
  }

  el.innerHTML = data
    .map(
      acc =>
        `${acc.bank_name} ${acc.bank_number} <b>/ ${acc.bank_owner}</b>`
    )
    .join(` <span style="color:#ff4d4d; font-weight:bold;">//</span> `);
}

/* ===========================================================
   🚀 초기 실행
=========================================================== */
loadBanners();
loadCategories();
loadProducts();
loadTodayDeal();
loadBankInfo();
updateCartCount();
updateCartPreview();

