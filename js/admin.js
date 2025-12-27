import { supabase } from "./supabaseClient.js";

/* ===========================================================
   유틸
=========================================================== */
const $ = (id) => document.getElementById(id);

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return isNaN(n) ? fallback : n;
}

/* ✅ 100원 단위 무조건 올림 */
function ceil100(price) {
  return Math.ceil(Number(price || 0) / 100) * 100;
}

/* ✅ 컴퓨터(노트북) 제외 판별 (item 기준) */
function isComputerItem(item) {
  const excludeCategories = ["노트북", "컴퓨터", "데스크탑", "전자기기", "PC"];
  const excludeKeywords = [
    "노트북", "laptop", "notebook", "macbook",
    "hp", "lenovo", "asus", "dell", "msi", "acer",
    "ssd", "ram", "cpu", "i5", "i7", "i9", "ryzen",
    "그래픽", "gpu", "rtx", "gtx"
  ];

  const cat = (item?.category || "").toLowerCase();
  const name = (item?.name || "").toLowerCase();

  const matchCategory = excludeCategories.some(c => cat.includes(c.toLowerCase()));
  const matchKeyword = excludeKeywords.some(k => name.includes(k.toLowerCase()));

  return matchCategory || matchKeyword;
}

/* ✅ 고니 규칙 묶음가격 계산 (fallback용) */
function calcBundlePrice(unitPrice, qty) {
  const ratio2 = 19900 / 13900;
  const ratio3 = 26900 / 13900;

  const u = safeNumber(unitPrice, 0);
  const q = Math.max(1, safeNumber(qty, 1));

  const price1 = Math.round(u);
  const price2 = Math.round(u * ratio2);
  const price3 = Math.round(u * ratio3);

  let result = 0;

  if (q === 1) result = price1;
  else if (q === 2) result = price2;
  else if (q === 3) result = price3;
  else {
    const diff = price3 - price2;
    result = price3 + (q - 3) * diff;
  }

  return ceil100(result);
}

/* ✅ totalPrice가 없을 때만 쓰는 fallback 계산 */
function calcFallbackTotalPrice(item) {
  const unitPrice = safeNumber(item.unitPrice ?? item.price ?? 0, 0);
  const qty = Math.max(1, safeNumber(item.qty ?? 1, 1));

  const bundleEnabled = item.bundle_enabled !== false;
  const excluded = isComputerItem(item) || !bundleEnabled;

  if (excluded) {
    return ceil100(Math.round(unitPrice * qty));
  }
  return calcBundlePrice(unitPrice, qty);
}

/* ✅ 주문 total 계산(최종 규칙) : sum(item.totalPrice) */
function calcOrderTotalByItems(items) {
  const safeItems = (items ?? []).map(it => ({ ...it }));

  safeItems.forEach(item => {
    const tp = safeNumber(item.totalPrice ?? 0, 0);
    if (!tp || tp <= 0) item.totalPrice = calcFallbackTotalPrice(item);
    else item.totalPrice = ceil100(tp);

    item.qty = Math.max(1, safeNumber(item.qty ?? 1, 1));
  });

  const total = safeItems.reduce((sum, i) => sum + safeNumber(i.totalPrice ?? 0, 0), 0);
  const totalQty = safeItems.reduce((sum, i) => sum + safeNumber(i.qty ?? 0, 0), 0);

  return { total, totalQty, items: safeItems };
}

/* ===========================================================
   ✅ 주문 item에 bundle_enabled 주입
=========================================================== */
let _productBundleMapCache = null;
let _productBundleMapCacheTime = 0;

async function getProductBundleMap() {
  const now = Date.now();
  if (_productBundleMapCache && (now - _productBundleMapCacheTime) < 30000) {
    return _productBundleMapCache;
  }

  const { data: products, error } = await supabase
    .from("products")
    .select("id, bundle_enabled");

  if (error) {
    console.error("getProductBundleMap error:", error);
    return {};
  }

  const map = {};
  (products ?? []).forEach(p => {
    map[String(p.id)] = (p.bundle_enabled !== false);
  });

  _productBundleMapCache = map;
  _productBundleMapCacheTime = now;

  return map;
}

function getItemProductId(item) {
  return (
    item?.productId ??
    item?.product_id ??
    item?.pid ??
    item?.id ??
    item?.productIdStr ??
    null
  );
}

async function applyBundleEnabledToOrderItems(orderItems) {
  const map = await getProductBundleMap();
  const items = (orderItems ?? []).map(it => ({ ...it }));

  items.forEach(it => {
    if (it.bundle_enabled === true || it.bundle_enabled === false) return;

    const pid = getItemProductId(it);
    if (!pid) return;

    const on = map[String(pid)];
    if (on === false) it.bundle_enabled = false;
    if (on === true) it.bundle_enabled = true;
  });

  return items;
}

/* ===========================================================
   페이지 전환 (전역 등록)
=========================================================== */
function showPage(page) {
  const main = $("main-area");
  if (!main) return;

  main.innerHTML = "";

  if (page === "products") loadProductPage();
  if (page === "categories") loadCategoryPage();
  if (page === "banners") loadBannerPage();
  if (page === "orders") loadOrderPage();
  if (page === "printed") loadPrintedPage();
  if (page === "account") loadAccountPage();
  if (page === "detailImages") loadDetailImagesPage();
}

window.showPage = showPage;

document.addEventListener("DOMContentLoaded", () => {
  if ($("main-area") && $("main-area").innerHTML.trim() === "") {
    showPage("products");
  }
});

/* ===========================================================
   ✅ 상품 관리 (정렬 고정 적용 완료)
=========================================================== */
async function loadProductPage() {
  const main = $("main-area");

  // ✅ 핵심 수정: 항상 ID 기준 정렬로 고정
  const { data: products } = await supabase
    .from("products")
    .select("*")
    .order("id", { ascending: true });

  const { data: categories } = await supabase
    .from("categories")
    .select("*")
    .order("id", { ascending: true });

  const catMap = {};
  categories?.forEach((c) => (catMap[c.id] = c.name));

  const rows = (products ?? [])
    .map((p) => {
      const stateText = p.sold_out ? "❌ 품절" : "✅ 판매중";
      const toggleText = p.sold_out ? "판매 재개" : "일시 품절";

      const bundleOn = p.bundle_enabled !== false;
      const bundleText = bundleOn ? "✅ 묶음ON" : "❌ 묶음OFF";

      return `
      <tr>
        <td>${p.id}</td>
        <td><img src="${p.image_url}" class="img-thumb"></td>
        <td>${p.name}</td>
        <td>${(p.price_original ?? 0).toLocaleString()}원</td>
        <td>${(p.price_sale ?? 0).toLocaleString()}원</td>
        <td>${catMap[p.category_id] ?? "없음"}</td>
        <td>${stateText}</td>
        <td>
          <button class="btn gray js-toggle-sold"
            data-id="${p.id}"
            data-state="${p.sold_out}">
            ${toggleText}
          </button>

          <button class="btn gray js-toggle-bundle"
            data-id="${p.id}"
            data-bundle="${bundleOn}">
            ${bundleText}
          </button>

          <button class="btn blue js-edit" data-id="${p.id}">수정</button>
          <button class="btn red js-del" data-id="${p.id}">삭제</button>
        </td>
      </tr>
    `;
    })
    .join("");

  main.innerHTML = `
    <h3>상품 관리</h3>
    <button class="btn green" onclick="addProduct()">상품 추가</button>

    <table>
      <tr>
        <th>ID</th>
        <th>이미지</th>
        <th>상품명</th>
        <th>정상가</th>
        <th>판매가</th>
        <th>카테고리</th>
        <th>상태</th>
        <th>관리</th>
      </tr>
      ${rows}
    </table>
  `;

  main.querySelectorAll(".js-edit").forEach((btn) => {
    btn.addEventListener("click", () => window.editProduct(btn.dataset.id));
  });

  main.querySelectorAll(".js-del").forEach((btn) => {
    btn.addEventListener("click", () => window.deleteProduct(btn.dataset.id));
  });

  main.querySelectorAll(".js-toggle-sold").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const current = btn.dataset.state === "true";

      await supabase.from("products").update({ sold_out: !current }).eq("id", id);

      _productBundleMapCache = null;
      loadProductPage();
    });
  });

  main.querySelectorAll(".js-toggle-bundle").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const current = btn.dataset.bundle === "true";
      const next = !current;

      await supabase.from("products").update({ bundle_enabled: next }).eq("id", id);

      _productBundleMapCache = null;
      loadProductPage();
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

  const { data: cats } = await supabase.from("categories").select("*").order("id", { ascending: true });

  const rows = (cats ?? [])
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

  const { error } = await supabase.from("categories").update({ name: newName.trim() }).eq("id", id);

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

  const { data: banners } = await supabase.from("banners").select("*").order("id", { ascending: false });

  const rows = (banners ?? [])
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

  const { error: uploadError } = await supabase.storage.from("kshop").upload(path, file, { upsert: true });

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
   주문 관리 (출력 전 주문 목록)
=========================================================== */
async function loadOrderPage() {
  const main = $("main-area");

  const { data: orders, error } = await supabase
    .from("orders")
    .select("*")
    .or("printed.is.null,printed.eq.false")
    .order("created_at", { ascending: false });

  if (error) {
    console.error(error);
    return alert("주문 목록을 불러오지 못했습니다.");
  }

  const rows = await Promise.all((orders ?? []).map(async (o) => {
    const items = await applyBundleEnabledToOrderItems((o.items ?? []).map(it => ({ ...it })));
    const { total, totalQty } = calcOrderTotalByItems(items);

    const agreeText = o.marketing_agree ? "✅ 동의" : "❌ 미동의";
    const dateRaw = o.created_at ?? o.createdAt ?? "";
    const dateText = dateRaw ? String(dateRaw).split("T")[0] : "";

    return `
      <tr>
        <td>${o.id ?? "-"}</td>
        <td>${o.name ?? "-"}</td>
        <td>${agreeText}</td>
        <td>${Number(total || 0).toLocaleString()}원</td>
        <td>${totalQty}</td>
        <td>${dateText}</td>
        <td>
          <button class="btn blue js-order-print" data-id="${o.id}">출력</button>
          <button class="btn red js-order-del" data-id="${o.id}">삭제</button>
        </td>
      </tr>`;
  }));

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
      ${rows.join("") || `<tr><td colspan="7" style="text-align:center;">주문이 없습니다.</td></tr>`}
    </table>
  `;

  main.querySelectorAll(".js-order-print").forEach((btn) => {
    btn.addEventListener("click", () => window.printOrder(btn.dataset.id));
  });

  main.querySelectorAll(".js-order-del").forEach((btn) => {
    btn.addEventListener("click", () => window.deleteOrder(btn.dataset.id));
  });
}

/* ===========================================================
   ✅ 주문 출력 기능
=========================================================== */
window.printOrder = async function (orderId) {
  if (!orderId) return alert("❌ 주문 ID가 없습니다.");

  const { data: o, error } = await supabase.from("orders").select("*").eq("id", orderId).single();

  if (error || !o) {
    console.error(error);
    return alert("주문 데이터를 불러오지 못했습니다.");
  }

  const items = await applyBundleEnabledToOrderItems((o.items ?? []).map(it => ({ ...it })));
  const { total, items: fixedItems } = calcOrderTotalByItems(items);
  const finalTotal = total;

  const popup = window.open("", "_blank");

  popup.document.write(`
    <html>
    <head>
      <title>주문서</title>
      <style>
        body { font-family: Arial; padding:20px; }
        table, th, td { border:1px solid #444; border-collapse:collapse; padding:8px; }
        th { background:#f2f2f2; }
      </style>
    </head>
    <body>
      <h2>주문서 - ${o.id}</h2>

      <p><b>고객명:</b> ${o.name ?? ""}</p>
      <p><b>연락처:</b> ${o.phone ?? ""}</p>
      <p><b>주소:</b> ${o.address ?? ""}</p>
      <p><b>요청사항:</b> ${o.memo ?? ""}</p>

      <h3>주문 내역</h3>
      <table>
        <tr><th>상품</th><th>수량</th><th>금액(확정)</th></tr>
        ${fixedItems.map(i => `
          <tr>
            <td>${i.name ?? ""} ${(isComputerItem(i) || i?.bundle_enabled === false) ? "(묶음 제외 ❌)" : "(묶음 적용 ✅)"}</td>
            <td>${safeNumber(i.qty ?? 1, 1)}</td>
            <td>${Number(i.totalPrice || 0).toLocaleString()}원</td>
          </tr>
        `).join("")}
      </table>

      <h3>총액: ${Number(finalTotal || 0).toLocaleString()}원</h3>

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
   출력된 주문 목록
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

  const rows = await Promise.all((printed ?? []).map(async (o) => {
    const items = await applyBundleEnabledToOrderItems((o.items ?? []).map(it => ({ ...it })));
    const { total, totalQty } = calcOrderTotalByItems(items);

    const agreeText = o.marketing_agree ? "✅ 동의" : "❌ 미동의";
    const printedAtRaw = o.printed_at ?? "";
    const printedDate = printedAtRaw ? String(printedAtRaw).split("T")[0] : "";

    return `
      <tr>
        <td>${o.id ?? "-"}</td>
        <td>${o.name ?? "-"}</td>
        <td>${agreeText}</td>
        <td>${Number(total || 0).toLocaleString()}원</td>
        <td>${totalQty}</td>
        <td>${printedDate}</td>
        <td><button class="btn red js-printed-del" data-id="${o.id}">삭제</button></td>
      </tr>`;
  }));

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
      ${rows.join("") || `<tr><td colspan="7" style="text-align:center;">출력된 주문이 없습니다.</td></tr>`}
    </table>
  `;

  main.querySelectorAll(".js-printed-del").forEach((btn) => {
    btn.addEventListener("click", () => window.deleteOrder(btn.dataset.id));
  });
}

/* ===========================================================
   주문 삭제
=========================================================== */
window.deleteOrder = async function (orderId) {
  if (!orderId) {
    alert("❌ 주문 ID가 없습니다. 삭제 중단");
    console.error("deleteOrder called with:", orderId);
    return;
  }

  if (!confirm("정말 이 주문을 삭제하시겠습니까?")) return;

  const { error, count } = await supabase.from("orders").delete({ count: "exact" }).eq("id", orderId);

  if (error) {
    console.error(error);
    alert("삭제 실패");
    return;
  }

  if (count !== 1) {
    alert("⚠️ 비정상 삭제 감지 – 작업 중단");
    console.warn("deleteOrder count:", count, "orderId:", orderId);
    return;
  }

  alert("삭제 완료");
  loadOrderPage();
};

/* ===========================================================
   XLSX 엑셀 저장
=========================================================== */
window.exportByPeriod = async function (type) {
  const { data } = await supabase.from("orders").select("*").eq("printed", true);

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

  for (const key of Object.keys(groups)) {
    const orders = groups[key];
    const rows = [];

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
      "상품목록(확정금액)",
    ]);

    for (const o of orders) {
      const items = await applyBundleEnabledToOrderItems((o.items ?? []).map(it => ({ ...it })));
      const { total, totalQty, items: fixedItems } = calcOrderTotalByItems(items);
      const finalTotal = total;

      const itemText = fixedItems
        .map((i) => `${i.name}(${i.qty}개 / ${Number(i.totalPrice || 0).toLocaleString()}원)`)
        .join(" / ");

      rows.push([
        o.id,
        o.name,
        o.phone,
        o.marketing_agree ? "TRUE" : "FALSE",
        o.address,
        o.memo,
        finalTotal,
        totalQty,
        o.printed_at.split("T")[0],
        itemText,
      ]);
    }

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
  }

  alert("엑셀 저장 완료!");
};

/* ===========================================================
   계좌 정보 관리
=========================================================== */
async function loadAccountPage() {
  const main = $("main-area");

  const { data: accounts } = await supabase.from("account_info").select("*");

  const rows = (accounts ?? [])
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

  const { data: products, error } = await supabase.from("products").select("*").order("id", { ascending: true });

  if (error) {
    console.error(error);
    return alert("상품 목록을 불러오지 못했습니다.");
  }

  const rows = (products ?? [])
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

  const { error: uploadError } = await supabase.storage.from("kshop").upload(filePath, file, { upsert: true });

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
  const { data: product } = await supabase.from("products").select("detail_image_url").eq("id", productId).single();

  if (product?.detail_image_url) {
    const path = product.detail_image_url.split("/").slice(4).join("/");
    await supabase.storage.from("kshop").remove([path]);
  }

  await supabase.from("products").update({ detail_image_url: null }).eq("id", productId);

  alert("삭제 완료!");
  loadDetailImagesPage();
};

window.editProduct = function (id) {
  location.href = `product_edit.html?id=${id}`;
};

window.deleteProduct = async function (productId) {
  if (!confirm("정말 이 상품을 삭제하시겠습니까?")) return;

  const { error } = await supabase.from("products").delete().eq("id", productId);

  if (error) {
    console.error(error);
    alert("상품 삭제 실패");
    return;
  }

  alert("상품이 삭제되었습니다.");
  _productBundleMapCache = null;
  loadProductPage();
};
