/* 실시간 채팅 클라이언트.
 *
 * ★ XSS 방지 ★
 * 서버에서 받은 메시지는 절대 innerHTML 로 넣지 않는다.
 * 항상 document.createTextNode / textContent 로만 출력하므로
 * "<script>alert(1)</script>" 같은 문자열이 와도 그냥 글자로 보인다.
 *
 * CSP(script-src 'self') 때문에 인라인 스크립트를 쓸 수 없으므로,
 * 필요한 값은 #chat-root 의 data-* 속성으로 전달받는다.
 */
(function () {
  "use strict";

  var root = document.getElementById("chat-root");
  if (!root || typeof io === "undefined") { return; }

  var mode = root.dataset.mode;               // "global" | "direct"
  var myId = root.dataset.me || "";
  var partnerId = root.dataset.partner || "";
  var maxLength = parseInt(root.dataset.maxlength || "500", 10);

  var log = document.getElementById("chat-log");
  var form = document.getElementById("chat-form");
  var input = document.getElementById("chat-input");
  var status = document.getElementById("chat-status");

  function setStatus(text, isError) {
    if (!status) { return; }
    status.textContent = text || "";
    status.classList.toggle("error", !!isError);
  }

  function formatTime(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? "" : d.toLocaleTimeString();
  }

  function appendMessage(msg) {
    var line = document.createElement("div");
    line.className = "chat-line" + (msg.sender_id === myId ? " mine" : "");

    var who = document.createElement("span");
    who.className = "who";
    who.textContent = msg.username;              // ← 텍스트로만 삽입

    var text = document.createElement("span");
    text.className = "text";
    text.textContent = msg.content;              // ← 텍스트로만 삽입 (HTML 해석 안 됨)

    var when = document.createElement("span");
    when.className = "when";
    when.textContent = formatTime(msg.created_at);

    line.appendChild(who);
    line.appendChild(text);
    line.appendChild(when);
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  if (log) { log.scrollTop = log.scrollHeight; }

  // 같은 출처로만 연결한다 (서버도 Origin 을 검증한다).
  var socket = io({ transports: ["websocket", "polling"], withCredentials: true });

  socket.on("connect", function () { setStatus("연결됨"); });
  socket.on("disconnect", function () { setStatus("연결이 끊어졌습니다. 새로고침 해주세요.", true); });
  socket.on("connect_error", function () {
    setStatus("연결할 수 없습니다. 로그인 상태를 확인해 주세요.", true);
  });
  socket.on("system", function (data) { setStatus(data && data.message ? data.message : ""); });
  socket.on("error_message", function (data) {
    setStatus(data && data.message ? data.message : "메시지를 보낼 수 없습니다.", true);
  });

  socket.on("global_message", function (msg) {
    if (mode === "global") { appendMessage(msg); }
  });

  socket.on("private_message", function (msg) {
    if (mode !== "direct") { return; }
    var involved = (msg.sender_id === partnerId && msg.to === myId) ||
                   (msg.sender_id === myId && msg.to === partnerId);
    if (involved) { appendMessage(msg); }
  });

  if (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var content = (input.value || "").trim();
      if (!content) { return; }
      if (content.length > maxLength) {   // 서버에서도 다시 검증한다 (클라이언트 검증은 편의용)
        setStatus("메시지는 " + maxLength + "자 이하여야 합니다.", true);
        return;
      }
      if (mode === "global") {
        socket.emit("global_message", { content: content });
      } else {
        socket.emit("private_message", { to: partnerId, content: content });
      }
      input.value = "";
      setStatus("");
    });
  }
})();
