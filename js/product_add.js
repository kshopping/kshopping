import { supabase } from "./supabaseClient.js";

// 카테고리 불러오기
async function loadCategories() {
  const { data, error } = await supabase.from("categories").select("*");

  if (error) {
    console.error(error);
    alert("카테고리를 불러올 수 없습니다.");
    return;
  }

  const select = document.getElementById("category");

  // 카테고리 옵션 추가
  data.forEach(c => {
    const opt = document.createElement("option");
    opt.value = c.id;     // ★ 반드시 ID를 value로 사용
    opt.textContent = c.name;
    select.appendChild(opt);
  });
}

// 이미지 업로드 함수
async function uploadImage(file, pathPrefix) {
  if (!file) return null;

  const filePath = `${pathPrefix}/${Date.now()}_${file.name}`;

  const { error: uploadError } = await supabase.storage
    .from("kshop")
    .upload(filePath, file, { upsert: true });

  if (uploadError) {
    console.error(uploadError);
    alert("이미지 업로드 실패!");
    return null;
  }

  // 업로드한 이미지 URL 가져오기
  const {
    data: { publicUrl },
  } = supabase.storage.from("kshop").getPublicUrl(filePath);

  return publicUrl;
}

// 저장 버튼 클릭
document.getElementById("saveBtn").onclick = async function () {
  const name = document.getElementById("name").value.trim();
  const price_original = Number(document.getElementById("price_original").value);
  const price_sale = Number(document.getElementById("price_sale").value);
  const category_id = document.getElementById("category").value;
  const description = document.getElementById("description").value.trim();

  const imageFile = document.getElementById("image_file").files[0];
  const detailFile = document.getElementById("detail_file").files[0];

  if (!name || !price_original || !price_sale) {
    return alert("필수 입력값을 모두 입력하세요!");
  }

  // 대표 이미지 업로드
  const image_url = await uploadImage(imageFile, "products");

  // 상세 이미지 업로드
  const detail_image_url = await uploadImage(detailFile, "details");

  // 🔥 Supabase 저장 (created_at 제거)
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
    return;
  }

  alert("상품이 성공적으로 추가되었습니다!");
  location.href = "admin.html";
};

// 초기 실행
loadCategories();
