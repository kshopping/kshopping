<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>K-Shopping | 외국인 전용 한국 쇼핑</title>

  <style>
    body {
      margin: 0;
      font-family: Pretendard, -apple-system, BlinkMacSystemFont, sans-serif;
      background: #f5f5f5;
      color: #222;
    }

    .landing-wrap {
      max-width: 420px;
      margin: 0 auto;
      background: #fff;
      min-height: 100vh;
    }

    /* 상단 후킹 */
    .hero {
      padding: 28px 20px;
      background: linear-gradient(180deg, #fff4cc, #ffffff);
      text-align: center;
    }

    .hero h1 {
      font-size: 22px;
      font-weight: 900;
      line-height: 1.3;
      margin-bottom: 10px;
    }

    .hero p {
      font-size: 15px;
      color: #555;
      margin-bottom: 18px;
    }

    .cta-btn {
      width: 100%;
      padding: 14px 0;
      background: #ffcc33;
      border: none;
      border-radius: 12px;
      font-size: 17px;
      font-weight: 800;
      cursor: pointer;
    }

    .section {
      padding: 22px 20px;
    }

    .section h2 {
      font-size: 18px;
      font-weight: 800;
      margin-bottom: 12px;
    }

    .section p,
    .section li {
      font-size: 14px;
      color: #555;
      line-height: 1.5;
    }

    .trust {
      background: #f9fafb;
      border-top: 1px solid #eee;
      border-bottom: 1px solid #eee;
    }

    .trust ul {
      padding-left: 18px;
      margin: 0;
    }

    .fixed-cta {
      position: sticky;
      bottom: 0;
      background: #ffffffee;
      padding: 12px 16px;
      border-top: 1px solid #ddd;
    }

    .fixed-cta button {
      width: 100%;
      padding: 14px 0;
      background: #ffb700;
      border: none;
      border-radius: 12px;
      font-size: 16px;
      font-weight: 800;
      cursor: pointer;
    }
  </style>
</head>

<body>
  <div class="landing-wrap">

    <!-- 첫 화면 -->
    <section class="hero">
      <h1>
        외국인을 위한<br>
        한국 인기 상품 쇼핑
      </h1>
      <p>
        카드 없이 구매 가능<br>
        한국에서 바로 배송
      </p>
      <button class="cta-btn" onclick="goShop()">지금 구매하기</button>
    </section>

    <!-- 대상 -->
    <section class="section">
      <h2>이런 분께 추천합니다</h2>
      <p>
        ✔ 한국 상품을 믿고 구매하고 싶은 분<br>
        ✔ 해외 카드 결제가 어려운 외국인<br>
        ✔ 전화·현금 송금으로 빠르게 주문하고 싶은 분
      </p>
    </section>

    <!-- 신뢰 -->
    <section class="section trust">
      <h2>안심 포인트</h2>
      <ul>
        <li>✔ 한국 현지 운영 쇼핑몰</li>
        <li>✔ 실시간 상담 가능</li>
        <li>✔ 검증된 정품 상품</li>
      </ul>
    </section>

    <!-- 혜택 -->
    <section class="section">
      <h2>지금 주문 혜택</h2>
      <p>
        🎁 한정 수량 특가<br>
        🚚 빠른 출고 진행
      </p>
    </section>

    <!-- 하단 CTA -->
    <div class="fixed-cta">
      <button onclick="goShop()">상품 보러가기</button>
    </div>

  </div>

  <script>
    function goShop() {
      // 👉 메인 쇼핑몰 또는 특정 상품 상세로 연결
      window.location.href = "index.html";
    }
  </script>
</body>
</html>

