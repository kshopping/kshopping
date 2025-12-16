import { supabase } from "./supabaseClient.js";

/* ===========================================================
   카테고리 불러오기
=========================================================== */
async function loadCategories() {
  const select = document.getElementById("category");
  if (!select) return;

  select.innerHTML = `<option value="">카테고리 선택</option>`;

  const { data, error } = await supabase
    .from("categories")
    .select("*")
    .order("name");

  if (error) {
    console.error(error);
    alert("카테고리를 불러올 수 없습니다.");
    return;
  }

  data.forEach((c) => {
    const opt = document.createElement("option");
    opt.value = c.id;
    opt.textContent = c.name;
    select.appendChild(opt);
  });
}

/* ===========================================================
   이미지 업로드 공통 함수
=========================================================== */
async function uploadImage(file, folder) {
  if (!file) return null;

  const filePath = `${folder}/${Date.now()}_${file.name}`;

  const { error: uploadError } = await supabase.storage
    .from("kshop")
    .upload(filePath, file, { upsert: true });

  if (uploadError) {
    console.error(uploadError);
    alert("이미지 업로드 실패!");
    return null;
  }

  const { data } = supabase.storage
    .from("kshop")
    .getPublicUrl(filePath);

  return data.publicUrl;
}

/* ===========================================================
   상품 저장
=========================================================== */
document.getElementById("saveBtn").addEventListener("click", async function (e) {
  // 🔥 중복 클릭 방지
  e.target.disabled = true;

  // DOM 안전 체크
  const nameEl = document.getElementById("name");
  const priceOriginalEl = document.getElementById("price_original");
  const priceSaleEl = document.getElementById("price_sale");
  const categoryEl = document.getElementById("category");
  const descEl = document.getElementById("description");

  if (!nameEl || !priceOriginalEl || !priceSaleEl) {
    alert("폼 요소가 존재하지 않습니다.");
    e.target.disabled = false;
    return;
  }

  const name = nameEl.value.trim();
  const price_original = Number(priceOriginalEl.value);
  const price_sale = Number(priceSaleEl.value);
  const category_id = categoryEl?.value || null;
  const description = descEl?.value.trim() || "";

  if (!name || !price_original || !price_sale) {
    alert("필수 항목을 모두 입력하세요.");
    e.target.disabled = false;
    return;
  }

  const imageFile = document.getElementById("image_file")?.files[0] || null;
  const detailFile = document.getElementById("detail_file")?.files[0] || null;

  // 이미지 업로드
  const image_url = await uploadImage(imageFile, "products");
  const detail_image_url = await uploadImage(detailFile, "details");

  // DB 저장
  const { error } = await supabase.from("products").insert({
    name,
    price_original,
    price_sale,
    category_id,
    image_url,
    detail_image_url,
    desc: description
  });

  if (error) {
    console.error(error);
    alert("상품 저장 중 오류가 발생했습니다.");
    e.target.disabled = false;
    return;
  }

  alert("상품이 성공적으로 추가되었습니다!");

  // 🔥 replace 사용 (뒤로가기·중복 실행 완전 차단)
  location.replace("admin.html");
});

/* ===========================================================
   초기 실행
=========================================================== */
loadCategories();
