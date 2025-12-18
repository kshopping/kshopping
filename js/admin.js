import { supabase } from "./supabaseClient.js";

/* ===========================================================
   유틸
=========================================================== */
const $ = (id) => document.getElementById(id);

/* ===========================================================
   페이지 전환
=========================================================== */
window.showPage = function (page) {
  $("main-area").innerHTML = "";

  if (page === "products") loadProductPage();
  if (page === "categories") loadCategoryPage();
  if (page === "banners") loadBannerPage();
  if (page === "orders") loadOrderPage();
  if (page === "printed") loadPrintedPage();
  if (page === "account") loadAccountPage();
  if (page === "detailImages") loadDetailImagesPage();
};

/* ===========================================================
   상품 관리
=========================================================== */
async function loadProductPage() {
  const main = $("main-area");

  const { data: products } = await supabase.from("products").select("*");
  const { data: categories } = await supabase.from("categories").select("*");

  const catMap = {};
  categories?.forEach((c) => (catMap[c.id] = c.name));

  // ✅ 여기부터 변경: inline onclick 제거하고 data-id로만 박음
  const rows = (products ?? [])
    .map(
      (p) => `
      <tr>
        <td>${p.id}</td>
        <td><img src="${p.image_url}" class="img-thumb"></td>
        <td>${p.name}</td>
        <td>${p.price_original.toLocaleString()}원</td>
        <td>${p.price_sale.toLocaleString()}원</td>
        <td>${catMap[p.category_id] ?? "없음"}</td>
        <td>
          <button class="btn blue js-edit" data-id="${p.id}">수정</button>
          <button class="btn red js-del" data-id="${p.id}">삭제</button>
        </td>
      </tr>
    `
    )
    .join("");

  main.innerHTML = `
    <h3>상품 관리</h3>
    <button class="btn green" onclick="addProduct()">상품 추가</button>

    <table>
      <tr>
        <th>ID</th><th>이미지</th><th>상품명</th>
        <th>정상가</th><th>판매가</th><th>카테고리</th><th>관리</th>
      </tr>
      ${rows}
    </table>
  `;

  // ✅ 여기부터 변경: JS에서 클릭 이벤트 연결 (이 방식은 무조건 됨)
  main.querySelectorAll(".js-edit").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      window.editProduct(id);
    });
  });

  main.querySelectorAll(".js-del").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      window.deleteProduct(id);
    });
  });
}

window.addProduct = function () {
  location.href = "product_add.html";
};

/* ===========================================================
   카테고리 관리
=========================================================== */
async function loadCategoryPage() {
  const main = $("main-area");

  const { data: cats } = await supabase.from("categories").select("*");

  const rows = cats
    .map(
      (c) => `
      <tr>
        <td>${c.id}</td>
        <td>${c.name}</td>
        <td>
          <button class="btn blue" onclick="editCategory('${c.id}', '${c.name}')">수정</button>
          <button class="btn red" onclick="deleteCategory('${c.id}')">삭제</button>
        </td>
      </tr>`
    )
    .join("");

  main.innerHTML = `
    <h3>카테고리 관리</h3>

    <input id="new_cat" placeholder="새 카테고리명">
    <button class="btn green" onclick="addCategory()">추가</button>

    <table>
      <tr><th>ID</th><th>이름</th><th>관리</th></tr>
      ${rows}
    </table>
  `;
}

window.addCategory = async function () {
  const name = $("new_cat").value.trim();
  if (!name) return alert("카테고리명을 입력하세요.");

  const newId = "cat_" + Date.now();

  const { error } = await supabase.from("categories").insert({
    id: newId,
    name,
  });

  if (error) {
    console.error(error);
    return alert("카테고리 추가 실패!");
  }

  alert("추가 완료!");
  loadCategoryPage();
};

window.editCategory = async function (id, oldName) {
  const newName = prompt("새 카테고리 이름을 입력하세요:", oldName);

  if (!newName || newName.trim() === "") {
    alert("수정이 취소되었습니다.");
    return;
  }

  const { error } = await supabase
    .from("categories")
    .update({ name: newName.trim() })
    .eq("id", id);

  if (error) {
    console.error(error);
    alert("카테고리 수정 실패!");
    return;
  }

  alert("수정 완료!");
  loadCategoryPage();
};

window.deleteCategory = async function (id) {
  await supabase.from("categories").delete().eq("id", id);
  loadCategoryPage();
};

/* ===========================================================
   배너 관리
=========================================================== */
async function loadBannerPage() {
  const main = $("main-area");

  const { data: banners } = await supabase
    .from("banners")
    .select("*")
    .order("id", { ascending: false });

  const rows = banners
    .map(
      (b) => `
      <tr>
        <td>${b.id}</td>
        <td><video src="${b.video_url}" class="banner-video" muted autoplay loop></video></td>
        <td>${b.video_url}</td>
        <td><button class="btn red" onclick="deleteBanner(${b.id})">삭제</button></td>
      </tr>`
    )
    .join("");

  main.innerHTML = `
    <h3>배너 관리</h3>

    <input id="banner_file" type="file" accept="video/*">
    <button class="btn green" onclick="addBanner()">업로드</button>

    <table>
      <tr><th>ID</th><th>미리보기</th><th>URL</th><th>관리</th></tr>
      ${rows}
    </table>
  `;
}

window.addBanner = async function () {
  const file = document.getElementById("banner_file").files[0];
  if (!file) return alert("파일을 선택하세요.");

  const path = `banners/${Date.now()}_${file.name}`;

  const { error: uploadError } = await supabase.storage
    .from("kshop")
    .upload(path, file, { upsert: true });

  if (uploadError) {
    console.error(uploadError);
    return alert("업로드 실패!");
  }

  const { data: { publicUrl } } = supabase.storage.from("kshop").getPublicUrl(path);

  const { error } = await supabase.from("banners").insert({
    video_url: publicUrl,
    sort_order: 1,
  });

  if (error) {
    console.error(error);
    return alert("DB 저장 실패!");
  }

  alert("업로드 완료!");
  loadBannerPage();
};

window.deleteBanner = async function (id) {
  await supabase.from("banners").delete().eq("id", id);
  loadBannerPage();
};

/* ===========================================================
   주문 관리 (출력 전 주문 목록)  ✅ 안전 수정
=========================================================== */
async function loadOrderPage() {
  const main = $("main-area");

  const { data: orders, error } = await supabase
    .from("orders")
    .select("*")
    .eq("printed", false)
    .order("created_at", { ascending: false });

  if (error) {
    console.error(error);
    return alert("주문 목록을 불러오지 못했습니다.");
  }

  const rows = (orders ?? [])
    .map((o) => {
      const qty = (o.items ?? []).reduce((t, i) => t + (i.qty ?? 0), 0);

      const agreeText = o.marketing_agree ? "✅ 동의" : "❌ 미동의";
      return `
      <tr>
        <td>${o.id}</td>
        <td>${o.name}</td>
        <td>${agreeText}</td>
        <td>${Number(o.total || 0).toLocaleString()}원</td>
        <td>${qty}</td>
        <td>${o.created_at?.split("T")[0] ?? ""}</td>
        <td>
          <button class="btn blue js-order-print" data-id="${o.id}">출력</button>
          <button class="btn red js-order-del" data-id="${o.id}">삭제</button>
        </td>
      </tr>`;
    })
    .join("");

  main.innerHTML = `
    <h2>주문 관리 (출력 전)</h2>
    <table>
      <tr>
      <th>주문번호</th>
      <th>고객명</th>
      <th>광고동의</th>
      <th>금액</th>
      <th>수량</th>
      <th>일자</th>
      <th>관리</th>
  
      </tr>
      ${rows}
    </table>
  `;

  // ✅ inline onclick 제거: data-id 기반 이벤트 바인딩
  main.querySelectorAll(".js-order-print").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      window.printOrder(id);
    });
  });

  main.querySelectorAll(".js-order-del").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      window.deleteOrder(id);
    });
  });
}

/* ===========================================================
   주문 출력 기능  ✅ 방어 추가(안전)
=========================================================== */
window.printOrder = async function (orderId) {
  if (!orderId) {
    alert("❌ 주문 ID가 없습니다.");
    return;
  }

  const { data: o, error } = await supabase
    .from("orders")
    .select("*")
    .eq("id", orderId)
    .single();

  if (error || !o) {
    console.error(error);
    alert("주문 데이터를 불러오지 못했습니다.");
    return;
  }

  const popup = window.open("", "_blank");

  popup.document.write(`
    <html>
    <head>
      <title>주문서</title>
      <style>
        body { font-family: Arial; padding:20px; }
        table, th, td { border:1px solid #444; border-collapse:collapse; padding:8px; }
      </style>
    </head>
    <body>
      <h2>주문서 - ${o.id}</h2>

      <p><b>고객명:</b> ${o.name}</p>
      <p><b>연락처:</b> ${o.phone}</p>
      <p><b>주소:</b> ${o.address}</p>
      <p><b>요청사항:</b> ${o.memo}</p>

      <h3>주문 내역</h3>
      <table>
        <tr><th>상품</th><th>수량</th><th>금액</th></tr>
        ${(o.items ?? [])
          .map(
            (i) => `
          <tr>
            <td>${i.name}</td>
            <td>${i.qty}</td>
            <td>${(Number(i.price || 0) * Number(i.qty || 0)).toLocaleString()}원</td>
          </tr>`
          )
          .join("")}
      </table>

      <h3>총액: ${Number(o.total || 0).toLocaleString()}원</h3>

      <script>window.print();</script>
    </body>
    </html>
  `);

  popup.document.close();

  await supabase
    .from("orders")
    .update({
      printed: true,
      printed_at: new Date().toISOString(),
    })
    .eq("id", orderId);

  loadOrderPage();
  loadPrintedPage();
};

/* ===========================================================
   출력된 주문 목록  ✅ 삭제 버튼 안전 수정
=========================================================== */
async function loadPrintedPage() {
  const main = $("main-area");

  const { data: printed, error } = await supabase
    .from("orders")
    .select("*")
    .eq("printed", true)
    .order("printed_at", { ascending: false });

  if (error) {
    console.error(error);
    return alert("출력된 주문 목록을 불러오지 못했습니다.");
  }

  const rows = (printed ?? [])
    .map((o) => {
      const qty = (o.items ?? []).reduce((t, i) => t + (i.qty ?? 0), 0);
      const agreeText = o.marketing_agree ? "✅ 동의" : "❌ 미동의";
      return `
      <tr>
        <td>${o.id}</td>
        <td>${o.name}</td>
        <td>${agreeText}</td>
        <td>${Number(o.total || 0).toLocaleString()}원</td>
        <td>${qty}</td>
        <td>${o.printed_at?.split("T")[0] ?? ""}</td>
        <td><button class="btn red js-printed-del" data-id="${o.id}">삭제</button></td>
      </tr>`;
    })
    .join("");

  main.innerHTML = `
    <h2>출력된 주문 관리</h2>

    <div style="margin-bottom:15px;">
      <button class="btn green" onclick="exportByPeriod('day')">📅 일별 저장</button>
      <button class="btn green" onclick="exportByPeriod('month')">🗓 월별 저장</button>
      <button class="btn green" onclick="exportByPeriod('year')">📘 연도별 저장</button>
    </div>

    <table>
      <tr>
       <th>주문번호</th>
       <th>고객명</th>
       <th>광고동의</th>
       <th>금액</th>
       <th>수량</th>
       <th>출력일</th>
       <th>관리</th>
 
      </tr>
      ${rows}
    </table>
  `;

  // ✅ printed 삭제도 inline onclick 제거
  main.querySelectorAll(".js-printed-del").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      window.deleteOrder(id);
    });
  });
}

/* ===========================================================
   주문 삭제  ✅ 절대 안전 버전 (전체삭제 방지)
=========================================================== */
window.deleteOrder = async function (orderId) {
  if (!orderId) {
    alert("❌ 주문 ID가 없습니다. 삭제 중단");
    console.error("deleteOrder called with:", orderId);
    return;
  }

  if (!confirm("정말 이 주문을 삭제하시겠습니까?")) return;

  const { error, count } = await supabase
    .from("orders")
    .delete({ count: "exact" })
    .eq("id", orderId);

  if (error) {
    console.error(error);
    alert("삭제 실패");
    return;
  }

  // count가 1이 아니면, 조건이 이상하다는 뜻(대량삭제 방지)
  if (count !== 1) {
    alert("⚠️ 비정상 삭제 감지 – 작업 중단");
    console.warn("deleteOrder count:", count, "orderId:", orderId);
    return;
  }

  alert("삭제 완료");
  loadOrderPage();
 
};

// ===========================
// XLSX 엑셀 저장 기능 (광고동의 포함 최종본)
// ===========================
window.exportByPeriod = async function (type) {
  const { data } = await supabase
    .from("orders")
    .select("*")
    .eq("printed", true);

  if (!data || data.length === 0) {
    return alert("출력된 주문이 없습니다.");
  }

  const groups = {};

  data.forEach((o) => {
    const date = o.printed_at.split("T")[0];
    const [y, m, d] = date.split("-");

    let key = "";
    if (type === "day") key = `${y}-${m}-${d}`;
    if (type === "month") key = `${y}-${m}`;
    if (type === "year") key = `${y}`;

    if (!groups[key]) groups[key] = [];
    groups[key].push(o);
  });

  Object.keys(groups).forEach((key) => {
    const orders = groups[key];
    const rows = [];

    // ✅ 엑셀 헤더 (광고동의 포함)
    rows.push([
      "주문번호",
      "고객명",
      "연락처",
      "광고동의",
      "주소",
      "요청사항",
      "총금액",
      "총수량",
      "출력일",
      "상품목록",
    ]);

    orders.forEach((o) => {
      const qty = (o.items ?? []).reduce((t, i) => t + i.qty, 0);

      const itemText = (o.items ?? [])
        .map((i) => `${i.name}(${i.qty}개 × ${i.price}원)`)
        .join(" / ");

      rows.push([
        o.id,
        o.name,
        o.phone,
        o.marketing_agree ? "TRUE" : "FALSE", // ✅ 핵심
        o.address,
        o.memo,
        o.total,
        qty,
        o.printed_at.split("T")[0],
        itemText,
      ]);
    });

    const ws = XLSX.utils.aoa_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Orders");

    const filename =
      type === "day"
        ? `orders_day_${key}.xlsx`
        : type === "month"
        ? `orders_month_${key}.xlsx`
        : `orders_year_${key}.xlsx`;

    XLSX.writeFile(wb, filename);
  });

  alert("엑셀 저장 완료!");
};


/* ===========================================================
   계좌 정보 관리
=========================================================== */
async function loadAccountPage() {
  const main = $("main-area");

  const { data: accounts } = await supabase.from("account_info").select("*");

  const rows = accounts
    .map(
      (a) => `
      <tr>
        <td>${a.id}</td>
        <td>${a.bank_name}</td>
        <td>${a.bank_number}</td>
        <td>${a.bank_owner}</td>
        <td><button class="btn red" onclick="deleteAccount(${a.id})">삭제</button></td>
      </tr>`
    )
    .join("");

  main.innerHTML = `
    <h2>계좌 정보 관리</h2>

    <div class="account-form">
      <label>은행명</label>
      <input id="bankName">

      <label>계좌번호</label>
      <input id="bankNumber">

      <label>예금주</label>
      <input id="bankOwner">

      <button id="addAccountBtn" class="btn green">+ 계좌 추가</button>
    </div>

    <table>
      <tr>
        <th>ID</th><th>은행명</th><th>계좌번호</th><th>예금주</th><th>관리</th>
      </tr>
      ${rows}
    </table>
  `;

  document.getElementById("addAccountBtn").onclick = addAccount;
}

window.addAccount = async function () {
  const bank = $("bankName").value.trim();
  const number = $("bankNumber").value.trim();
  const owner = $("bankOwner").value.trim();

  if (!bank || !number || !owner) return alert("모든 입력칸을 채우세요.");

  await supabase.from("account_info").insert({
    bank_name: bank,
    bank_number: number,
    bank_owner: owner,
  });

  alert("계좌 추가 완료!");
  loadAccountPage();
};

window.deleteAccount = async function (id) {
  await supabase.from("account_info").delete().eq("id", id);
  loadAccountPage();
};

/* ===========================================================
   상세 이미지 관리
=========================================================== */
async function loadDetailImagesPage() {
  const main = $("main-area");

  const { data: products, error } = await supabase
    .from("products")
    .select("*")
    .order("id", { ascending: true });

  if (error) {
    console.error(error);
    return alert("상품 목록을 불러오지 못했습니다.");
  }

  const rows = products
    .map(
      (p) => `
    <tr>
      <td>${p.id}</td>
      <td>${p.name}</td>
      <td>
        <img src="${p.detail_image_url || p.image_url || ""}" 
             class="img-thumb" style="max-height:80px;">
      </td>
      <td>
        <input type="file" id="file_${p.id}" />
        <button class="btn blue" onclick="uploadDetailImage(${p.id})">업로드</button>
        <button class="btn red" onclick="deleteDetailImage(${p.id})">삭제</button>
      </td>
    </tr>
  `
    )
    .join("");

  main.innerHTML = `
    <h2>상세 이미지 관리</h2>
    <table>
      <tr>
        <th>ID</th>
        <th>상품명</th>
        <th>상세이미지</th>
        <th>관리</th>
      </tr>
      ${rows}
    </table>
  `;
}

window.uploadDetailImage = async function (productId) {
  const file = document.getElementById(`file_${productId}`).files[0];
  if (!file) return alert("파일을 선택하세요.");

  const filePath = `details/${productId}_${Date.now()}.jpg`;

  const { error: uploadError } = await supabase.storage
    .from("kshop")
    .upload(filePath, file, { upsert: true });

  if (uploadError) {
    console.error(uploadError);
    return alert("업로드 실패!");
  }

  const { data: { publicUrl } } = supabase.storage.from("kshop").getPublicUrl(filePath);

  await supabase.from("products").update({ detail_image_url: publicUrl }).eq("id", productId);

  alert("상세 이미지 업로드 완료!");
  loadDetailImagesPage();
};

window.deleteDetailImage = async function (productId) {
  const { data: product } = await supabase
    .from("products")
    .select("detail_image_url")
    .eq("id", productId)
    .single();

  if (product?.detail_image_url) {
    const path = product.detail_image_url.split("/").slice(4).join("/");
    await supabase.storage.from("kshop").remove([path]);
  }

  await supabase.from("products").update({ detail_image_url: null }).eq("id", productId);

  alert("삭제 완료!");
  loadDetailImagesPage();
};

/* ===========================================================
   상품 수정 페이지 이동
=========================================================== */
window.editProduct = function (id) {
  location.href = `product_edit.html?id=${id}`;
};

/* ===========================================================
   🗑 상품 삭제 (정식 버전)
=========================================================== */
window.deleteProduct = async function (productId) {
  if (!confirm("정말 이 상품을 삭제하시겠습니까?")) return;

  const { error } = await supabase.from("products").delete().eq("id", productId);

  if (error) {
    console.error(error);
    alert("상품 삭제 실패");
    return;
  }

  alert("상품이 삭제되었습니다.");
  loadProductPage();
};
