console.log("🔥 admin.js 실제 로드됨");
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
          <button class="btn blue" onclick="editProduct('${p.id}')">수정</button>
          <button class="btn red" onclick="deleteProduct('${p.id}')">삭제</button>
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
    name
  });

  if (error) {
    console.error(error);
    return alert("카테고리 추가 실패!");
  }

  alert("추가 완료!");
  loadCategoryPage();
};

window.editCategory = async function(id, oldName) {
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

  const {
    data: { publicUrl },
  } = supabase.storage.from("kshop").getPublicUrl(path);

  const { error } = await supabase.from("banners").insert({
    video_url: publicUrl,
    sort_order: 1
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
   주문 관리 (출력 전 주문 목록)
=========================================================== */
async function loadOrderPage() {
  const main = $("main-area");

  const { data: orders } = await supabase
    .from("orders")
    .select("*")
    .eq("printed", false)
    .order("created_at", { ascending: false });

  const rows = orders
    .map((o) => {
      const qty = o.items.reduce((t, i) => t + i.qty, 0);

      return `
      <tr>
        <td>${o.id}</td>
        <td>${o.name}</td>
        <td>${o.total.toLocaleString()}원</td>
        <td>${qty}</td>
        <td>${o.created_at?.split("T")[0]}</td>
        <td>
          <button class="btn blue" onclick="printOrder('${o.id}')">출력</button>
          <button class="btn red" onclick="deleteOrder('${o.id}')">삭제</button>
        </td>
      </tr>`;
    })
    .join("");

  main.innerHTML = `
    <h2>주문 관리 (출력 전)</h2>
    <table>
      <tr>
        <th>주문번호</th><th>고객명</th><th>금액</th>
        <th>수량</th><th>일자</th><th>관리</th>
      </tr>
      ${rows}
    </table>
  `;
}

/* ===========================================================
   주문 출력 기능
=========================================================== */
window.printOrder = async function (orderId) {
  const { data: o } = await supabase.from("orders").select("*").eq("id", orderId).single();

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
        ${o.items
          .map(
            (i) => `
          <tr>
            <td>${i.name}</td>
            <td>${i.qty}</td>
            <td>${(i.price * i.qty).toLocaleString()}원</td>
          </tr>`
          )
          .join("")}
      </table>

      <h3>총액: ${o.total.toLocaleString()}원</h3>

      <script>window.print();</script>
    </body>
    </html>
  `);

  popup.document.close();

  await supabase
    .from("orders")
    .update({
      printed: true,
      printed_at: new Date().toISOString()
    })
    .eq("id", orderId);

  loadOrderPage();
  loadPrintedPage();
};

/* ===========================================================
   출력된 주문 목록
=========================================================== */
async function loadPrintedPage() {
  const main = $("main-area");

  const { data: printed } = await supabase
    .from("orders")
    .select("*")
    .eq("printed", true)
    .order("printed_at", { ascending: false });

  const rows = printed
    .map((o) => {
      const qty = o.items.reduce((t, i) => t + i.qty, 0);

      return `
      <tr>
        <td>${o.id}</td>
        <td>${o.name}</td>
        <td>${o.total.toLocaleString()}원</td>
        <td>${qty}</td>
        <td>${o.printed_at?.split("T")[0]}</td>
        <td><button class="btn red" onclick="deleteOrder('${o.id}')">삭제</button></td>
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
        <th>주문번호</th><th>고객명</th><th>금액</th>
        <th>수량</th><th>출력일</th><th>관리</th>
      </tr>
      ${rows}
    </table>
  `;
}

/* ===========================================================
   출력된 주문 삭제
=========================================================== */
window.deleteOrder = async function (orderId) {
  await supabase.from("orders").delete().eq("id", orderId);
  loadOrderPage();
  loadPrintedPage();
};

// ===========================
// XLSX 엑셀 저장 기능 (안전모드)
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

    // 헤더
    rows.push([
      "주문번호",
      "고객명",
      "연락처",
      "주소",
      "요청사항",
      "총금액",
      "총수량",
      "출력일",
      "상품목록"
    ]);

    // 데이터
    orders.forEach((o) => {
      const qty = o.items.reduce((t, i) => t + i.qty, 0);

      const itemText = o.items
        .map((i) => `${i.name}(${i.qty}개 × ${i.price}원)`)
        .join(" / ");

      rows.push([
        o.id,
        o.name,
        o.phone,
        o.address,
        o.memo,
        o.total,
        qty,
        o.printed_at.split("T")[0],
        itemText
      ]);
    });

    // 워크시트 생성
    const ws = XLSX.utils.aoa_to_sheet(rows);

    // 워크북 생성
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, "Orders");

    // 파일명
    const filename =
      type === "day"
        ? `orders_day_${key}.xlsx`
        : type === "month"
        ? `orders_month_${key}.xlsx`
        : `orders_year_${key}.xlsx`;

    // 다운로드 실행
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
    bank_owner: owner
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

  const {
    data: { publicUrl },
  } = supabase.storage.from("kshop").getPublicUrl(filePath);

  await supabase
    .from("products")
    .update({ detail_image_url: publicUrl })
    .eq("id", productId);

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

  await supabase
    .from("products")
    .update({ detail_image_url: null })
    .eq("id", productId);

  alert("삭제 완료!");
  loadDetailImagesPage();
};

/* ===========================================================
   상품 수정 페이지 이동
=========================================================== */
window.editProduct = function (id) {
  location.href = `product_edit.html?id=${id}`;
};
