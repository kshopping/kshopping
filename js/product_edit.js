import { supabase } from "./supabaseClient.js";

// URL에서 상품 ID 가져오기
const params = new URLSearchParams(location.search);
const productId = params.get("id");

// DOM 가져오기
const $ = (id) => document.getElementById(id);

// 페이지 로드 → 상품 정보 불러오기
window.onload = async function () {
  // 카테고리 불러오기
  const { data: categories } = await supabase.from("categories").select("*");

  $("category").innerHTML = categories
    .map((c) => `<option value="${c.id}">${c.name}</option>`)
    .join("");

  // 상품 정보 불러오기
  const { data: p } = await supabase
    .from("products")
    .select("*")
    .eq("id", productId)
    .single();

  if (!p) return alert("상품을 찾을 수 없습니다!");

  $("name").value = p.name;
  $("price_original").value = p.price_original;
  $("price_sale").value = p.price_sale;
  $("category").value = p.category_id;
  $("desc").value = p.desc;
};

// 파일 업로드 함수
async function uploadImage(file, path) {
  if (!file) return null;

  const filePath = `${path}/${productId}_${Date.now()}.jpg`;

  const { error } = await supabase.storage
    .from("kshop")
    .upload(filePath, file, { upsert: true });

  if (error) {
    console.error(error);
    alert("이미지 업로드 실패!");
    return null;
  }

  const { data } = supabase.storage.from("kshop").getPublicUrl(filePath);
  return data.publicUrl;
}

// 수정 저장 버튼
$("saveBtn").onclick = async function () {
  const name = $("name").value;
  const price_original = Number($("price_original").value);
  const price_sale = Number($("price_sale").value);
  const category_id = $("category").value;
  const desc = $("desc").value;

  const imageFile = $("image_file").files[0];
  const detailFile = $("detail_file").files[0];

  let image_url = null;
  let detail_image_url = null;

  if (imageFile) image_url = await uploadImage(imageFile, "products");
  if (detailFile) detail_image_url = await uploadImage(detailFile, "details");

  const updateData = {
    name,
    price_original,
    price_sale,
    category_id,
    desc,
  };

  if (image_url) updateData.image_url = image_url;
  if (detail_image_url) updateData.detail_image_url = detail_image_url;

  const { error } = await supabase
    .from("products")
    .update(updateData)
    .eq("id", productId);

  if (error) {
    console.error(error);
    alert("상품 수정 중 오류 발생!");
    return;
  }

  alert("상품 수정 완료!");
  location.href = "admin.html";
};
