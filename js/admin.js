/************************************************************
 *  admin.js — Supabase + Storage + 상품 CRUD + 상세설명 CRUD
 ************************************************************/

import { supabase } from "./supabase.js";

const bucket = "kshop"; // Storage 버킷명
let products = [];
let categories = [];
let currentDetailId = null;

/************************************************************
 *  공통: 파일 이름 정리 (한글/특수문자 제거)
 ************************************************************/
function makeSafeFilePath(originalName, prefix = "") {
  const dot = originalName.lastIndexOf(".");
  const ext = dot !== -1 ? originalName.slice(dot + 1) : "";
  const baseRaw = dot !== -1 ? originalName.slice(0, dot) : originalName;

  // 한글/악센트 제거 → 영문/숫자/_/- 만 남기기
  const base = baseRaw
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9_-]/g, "") || "image";

  const ts = Date.now();
  const name = `${prefix}${base}_${ts}`;
  return ext ? `${name}.${ext}` : name;
}

/************************************************************
 *  초기 실행
 ************************************************************/
document.addEventListener("DOMContentLoaded", () => {
  console.log("🔥 admin.js loaded");
  loadCategories();
  loadProducts();
  initEvents();
});

/************************************************************
 *  카테고리 로드 (localStorage 유지)
 ************************************************************/
function loadCategories() {
  try {
    categories = JSON.parse(localStorage.getItem("categories")) || [
      { id: "laptop", name: "노트북" },
      { id: "pc", name: "데스크탑" },
      { id: "monitor", name: "모니터" },
      { id: "etc", name: "기타" },
    ];
  } catch {
    categories = [];
  }
}

/************************************************************
 *  상품 데이터 불러오기
 ************************************************************/
async function loadProducts() {
  const tbody = document.querySelector("#productTableBody");
  tbody.innerHTML =
    `<tr><td colspan="10" style="text-align:center;">⏳ 로딩 중...</td></tr>`;

  const { data, error } = await supabase
    .from("products")
    .select("*")
    .order("id");

  if (error) {
    console.error("loadProducts 오류:", error);
    alert("상품 데이터를 불러오지 못했습니다.\n" + (error.message || ""));
    return;
  }

  products = data || [];
  renderProductTable();
}

/************************************************************
 *  상품 테이블 렌더링
 ************************************************************/
function renderProductTable() {
  const tbody = document.querySelector("#productTableBody");
  tbody.innerHTML = "";

  products.forEach((p, i) => {
    const tr = document.createElement("tr");
    tr.dataset.id = p.id;

    tr.innerHTML = `
      <td>${i + 1}</td>
      <td><img class="img-thumb" src="${p.image_url || ""}" /></td>

      <td><input class="name" value="${p.name || ""}"></td>

      <td><select class="category"></select></td>

      <td><input class="orig" type="number" value="${p.price_original || 0}"></td>
      <td><input class="sale" type="number" value="${p.price_sale || 0}"></td>

      <td><input class="img-url" value="${p.image_url || ""}"></td>

      <td><button class="btn-detail">편집</button></td>

      <td><input type="file" class="img-file" accept="image/*"></td>

      <td>
        <button class="btn-save">수정</button>
        <button class="btn-del">삭제</button>
      </td>
    `;

    tbody.appendChild(tr);

    // 카테고리 옵션
    const select = tr.querySelector(".category");
    categories.forEach((c) => {
      const opt = document.createElement("option");
      opt.value = c.id;
      opt.textContent = c.name;
      if (c.id === p.category_id) opt.selected = true;
      select.appendChild(opt);
    });

    // 파일 선택 → 자동 업로드
    tr.querySelector(".img-file").addEventListener("change", (e) => {
      handleImageUpload(e, tr);
    });

    // 상세 편집기 열기
    tr.querySelector(".btn-detail").addEventListener("click", () => {
      openDetailEditor(p.id);
    });

    // 수정 저장
    tr.querySelector(".btn-save").addEventListener("click", () => {
      saveProductRow(p.id, tr);
    });

    // 삭제
    tr.querySelector(".btn-del").addEventListener("click", () => {
      deleteProduct(p.id);
    });
  });
}

/************************************************************
 *  일반 상품 이미지 업로드
 ************************************************************/
async function handleImageUpload(e, tr) {
  const file = e.target.files[0];
  if (!file) return;

  const filePath = makeSafeFilePath(file.name, "prod_");

  const { data: uploadData, error } = await supabase.storage
    .from(bucket)
    .upload(filePath, file, { upsert: true });

  if (error) {
    console.error("이미지 업로드 오류:", error);
    alert("이미지 업로드 실패!\n" + (error.message || ""));
    return;
  }

  const { data: publicData } = supabase.storage
    .from(bucket)
    .getPublicUrl(filePath);

  tr.querySelector(".img-url").value = publicData.publicUrl;
  tr.querySelector(".img-thumb").src = publicData.publicUrl;
  console.log("이미지 업로드 성공:", publicData.publicUrl);
}

/************************************************************
 *  단일 상품 저장
 ************************************************************/
async function saveProductRow(id, tr) {
  const updated = {
    id,
    name: tr.querySelector(".name").value.trim(),
    category_id: tr.querySelector(".category").value,
    price_original: Number(tr.querySelector(".orig").value || 0),
    price_sale: Number(tr.querySelector(".sale").value || 0),
    image_url: tr.querySelector(".img-url").value.trim(),
  };

  const { error } = await supabase.from("products").upsert(updated);

  if (error) {
    console.error("상품 저장 오류:", error);
    alert("상품 저장 실패!\n" + (error.message || ""));
    return;
  }

  alert("저장 완료!");
  loadProducts();
}

/************************************************************
 *  상품 삭제
 ************************************************************/
async function deleteProduct(id) {
  if (!confirm("정말 삭제할까요?")) return;

  const { error } = await supabase.from("products").delete().eq("id", id);

  if (error) {
    console.error("상품 삭제 오류:", error);
    alert("삭제 실패!\n" + (error.message || ""));
    return;
  }

  loadProducts();
}

/************************************************************
 *  상세 설명 에디터 열기
 ************************************************************/
async function openDetailEditor(productId) {
  currentDetailId = productId;

  const p = products.find((x) => x.id === productId);
  if (!p) return alert("상품을 찾을 수 없습니다.");

  document.querySelector("#detailSelectedName").textContent =
    `${p.id} / ${p.name}`;

  document.querySelector("#detailEditor").value = p.detail_desc || "";
  document.querySelector("#detailImgUrlInput").value = p.detail_image_url || "";

  document.querySelector("#detailEditorCard").scrollIntoView({
    behavior: "smooth",
  });
}

/************************************************************
 *  상세 설명 저장
 ************************************************************/
document
  .querySelector("#btnSaveDetail")
  .addEventListener("click", async () => {
    if (!currentDetailId) return alert("선택된 상품이 없습니다.");

    const detail = document.querySelector("#detailEditor").value;
    const detailImg = document
      .querySelector("#detailImgUrlInput")
      .value.trim();

    const { error } = await supabase
      .from("products")
      .update({ detail_desc: detail, detail_image_url: detailImg })
      .eq("id", currentDetailId);

    if (error) {
      console.error("상세설명 저장 오류:", error);
      alert("상세설명 저장 실패!\n" + (error.message || ""));
      return;
    }

    alert("상세 설명 저장 완료!");
    loadProducts();
  });

/************************************************************
 *  상세 이미지 파일 선택 → URL 자동 입력
 ************************************************************/
document
  .querySelector("#detailImgFileInput")
  .addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const filePath = makeSafeFilePath(file.name, "detail_");

    const { error } = await supabase.storage
      .from(bucket)
      .upload(filePath, file, { upsert: true });

    if (error) {
      console.error("상세 이미지 업로드 오류:", error);
      alert("상세 이미지 업로드 실패!\n" + (error.message || ""));
      return;
    }

    const { data } = supabase.storage.from(bucket).getPublicUrl(filePath);
    document.querySelector("#detailImgUrlInput").value = data.publicUrl;
    console.log("상세 이미지 업로드 성공:", data.publicUrl);
  });

/************************************************************
 *  기타 버튼 이벤트
 ************************************************************/
function initEvents() {
  document.querySelector("#btnClearDetail")?.addEventListener("click", () => {
    document.querySelector("#detailEditor").value = "";
    document.querySelector("#detailImgUrlInput").value = "";
  });

  document
    .querySelector("#btnAddProduct")
    .addEventListener("click", addNewProduct);

  document
    .querySelector("#btnSaveAllProducts")
    .addEventListener("click", saveAllProducts);
}

/************************************************************
 *  새 상품 추가
 ************************************************************/
async function addNewProduct() {
  const newId = "p" + Date.now();

  const newProduct = {
    id: newId,
    name: "새 상품",
    category_id: categories[0]?.id || "etc",
    price_original: 0,
    price_sale: 0,
    image_url: "",
  };

  const { error } = await supabase.from("products").insert(newProduct);

  if (error) {
    console.error("상품 추가 오류:", error);
    alert("상품 추가 실패!\n" + (error.message || ""));
    return;
  }

  loadProducts();
}

/************************************************************
 *  전체 저장 – 안내만
 ************************************************************/
async function saveAllProducts() {
  alert("전체 저장은 필요 없습니다. 모든 수정은 '수정' 버튼으로 개별 저장됩니다!");
}
