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
   ✅ 안전한 이미지 업로드 (한글 파일명 제거)
=========================================================== */
async function uploadImage(file, folder) {
  if (!file) return null;

  const ext = file.name.split(".").pop().toLowerCase();
  const safeName = `${Date.now()}.${ext}`;
  const filePath = `${folder}/${safeName}`;

  const { error } = await supabase.storage
    .from("kshop")
    .upload(filePath, file, {
      cacheControl: "3600",
      upsert: false
    });

  if (error) {
    console.error("이미지 업로드 실패:", error);
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
  e.target.disabled = true;

  const name = document.getElementById("name")?.value.trim();
  const price_original = Number(document.getElementById("price_original")?.value);
  const price_sale = Number(document.getElementById("price_sale")?.value);
  const category_id = document.getElementById("category")?.value || null;
  const desc = document.getElementById("desc")?.value.trim() || "";

  if (!name || !price_original || !price_sale) {
    alert("필수 항목을 모두 입력하세요.");
    e.target.disabled = false;
    return;
  }

  const imageFile = document.getElementById("image_file")?.files[0] || null;
  const detailFile = document.getElementById("detail_file")?.files[0] || null;

  const image_url = await uploadImage(imageFile, "products");
  const detail_image_url = await uploadImage(detailFile, "details");

  const { error } = await supabase.from("products").insert({
    name,
    price_original,
    price_sale,
    category_id,
    image_url,
    detail_image_url,
    desc
  });

  if (error) {
    console.error(error);
    alert("상품 저장 중 오류가 발생했습니다.");
    e.target.disabled = false;
    return;
  }

  alert("상품이 성공적으로 추가되었습니다!");
alert("상품이 성공적으로 추가되었습니다!");
history.back();

});

/* ===========================================================
   초기 실행
=========================================================== */
loadCategories();
