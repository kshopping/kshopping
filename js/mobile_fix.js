// js/mobile_fix.js
(function () {
  function setRealVh() {
    // 모바일 브라우저 주소창/하단바 포함 실제 높이 보정
    const vh = window.innerHeight * 0.01;
    document.documentElement.style.setProperty('--vh', `${vh}px`);
  }

  // 첫 로딩 시 설정
  setRealVh();

  // 회전/주소창 숨김/키보드 등 변화 대응
  window.addEventListener('resize', setRealVh);
  window.addEventListener('orientationchange', setRealVh);

  // iOS/삼성 브라우저에서 일부 상황 대응 (스크롤 시 주소창 변화)
  let lastH = window.innerHeight;
  window.addEventListener('scroll', () => {
    if (Math.abs(window.innerHeight - lastH) > 50) {
      lastH = window.innerHeight;
      setRealVh();
    }
  });
})();
