import { supabase } from "./supabaseClient.js";

/* ===========================================================
   카테고리 
=========================================================== */
const categorySelect = document.getElementById("category");
const subcategorySelect = document.getElementById("subcategory");

/* ===========================================================
   카테고리 선택 이벤트
=========================================================== */
if (categorySelect) {
  categorySelect.addEventListener("change", async () => {
    const category = categorySelect.value;
    await loadSubcategories(category);
  });
}

/* ===========================================================
   서브카테고리 로드
=========================================================== */
async function loadSubcategories(category) {
  if (!subcategorySelect) return;

  subcategorySelect.innerHTML = "<option value=''>로딩 중...</option>";

  const { data, error } = await supabase
    .from("subcategories")
    .select("*")
    .eq("category", category)
    .order("name", { ascending: true });

  if (error) {
    console.error("서브카테고리 불러오기 오류:", error);
    subcategorySelect.innerHTML = "<option value=''>불러오기 실패</option>";
    return;
  }

  subcategorySelect.innerHTML = "<option value=''>선택하세요</option>";
  data.forEach((sub) => {
    const option = document.createElement("option");
    option.value = sub.name;
    option.textContent = sub.name;
    subcategorySelect.appendChild(option);
  });
}

/* ===========================================================
   상품 등록
=========================================================== */
const addForm = document.getElementById("addProductForm");

if (addForm) {
  addForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const name = document.getElementById("name")?.value.trim();
    const price = Number(document.getElementById("price")?.value);
    const imageInput = document.getElementById("image");
    const category = document.getElementById("category")?.value;
    const subcategory = document.getElementById("subcategory")?.value || null;
    const description = document.getElementById("description")?.value.trim();

    if (!name || !price || !category || !imageInput?.files?.length) {
      alert("⚠️ 상품명/가격/카테고리/이미지는 필수입니다.");
      return;
    }

    const file = imageInput.files[0];
    const fileExt = file.name.split(".").pop();
    const fileName = `${Date.now()}.${fileExt}`;
    const filePath = `products/${fileName}`;

    // ✅ 이미지 업로드
    const { error: uploadError } = await supabase.storage
      .from("product-images")
      .upload(filePath, file);

    if (uploadError) {
      console.error("이미지 업로드 실패:", uploadError);
      alert("⚠️ 이미지 업로드 실패");
      return;
    }

    const { data: urlData } = supabase.storage
      .from("product-images")
      .getPublicUrl(filePath);

    const imageUrl = urlData.publicUrl;

    // ✅ DB 저장
    const { error: insertError } = await supabase.from("products").insert([
      {
        name,
        price,
        image: imageUrl,
        category,
        subcategory,
        description,
      },
    ]);

    if (insertError) {
      console.error("상품 저장 실패:", insertError);
      alert("⚠️ 상품 저장 실패");
      return;
    }

    // ✅ (버그 수정) alert 2번 뜨던 문제 제거
    alert("상품이 성공적으로 추가되었습니다!");

    // ✅ 폼 초기화
    addForm.reset();
    subcategorySelect.innerHTML = "<option value=''>선택하세요</option>";
  });
}
