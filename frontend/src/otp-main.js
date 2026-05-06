import { createApp, reactive, ref, computed, watch } from "vue/dist/vue.esm-bundler.js";
import "./otp.css";

const translationsEn = {
  "eyebrow": "iCash Security",
  "brand_title": "OTP Access<br>for iCash",
  "brand_copy": "Securely verify your identity via OTP to access iCash system with confidence, both in testing and production.",
  "step1_title": "Enter Phone Number",
  "step1_desc": "Supports local Cambodia numbers or international E.164 format",
  "step2_title": "Receive OTP",
  "step2_desc": "System will send the code via the configured SMS provider",
  "step3_title": "Verify to Access",
  "step3_desc": "Enter the 6-digit code to complete the verification process",
  "footer_left": "Secure sign-in experience for internal testing",
  "footer_right": "OTP Backend Service",
  "kicker": "Verification",
  "header_h1": "Verify Identity to Sign In",
  "header_p": "Enter your phone number to request an OTP, then enter the 6-digit code received to verify your identity.",
  "label_phone": "Phone Number",
  "control_language": "Language",
  "control_theme": "Theme",
  "placeholder_phone": "0971234567 or +855971234567",
  "btn_request": "Request OTP",
  "label_otp": "6-digit OTP",
  "placeholder_otp": "123456",
  "btn_verify": "Verify Code",
  "note": "For actual testing, the SMS provider and sending permissions depend on the system environment configuration.",
  "status_phone_invalid": "Please enter a valid phone number",
  "status_server_error": "Unable to connect to server",
  "request_failed": "Unable to request OTP",
  "request_success": "OTP was sent successfully",
  "verify_prompt": "Please enter a 6-digit OTP",
  "verify_failed": "Invalid OTP code",
  "verify_success": "OTP verified successfully.",
  "utility_title": "OTP Hub"
};

const translations = {
  en: translationsEn,
  th: translationsEn,
  kh: translationsEn
};

function getFetchErrorMessage(data, fallback) {
  return data?.detail || data?.message || fallback;
}

createApp({
  setup() {
    const currentLang = ref(localStorage.getItem("otp_lang") || "th");
    const currentTheme = ref(localStorage.getItem("icash_theme") || "light");
    const text = computed(() => translations[currentLang.value] || translations.en);
    const state = reactive({
      phone: "",
      otp: "",
      requestLocked: false,
      verifyLocked: false,
      requestLoading: false,
      verifyLoading: false,
      showVerify: false,
      status: {
        message: "",
        type: "success"
      }
    });

    function applyUiState() {
      document.documentElement.dataset.theme = currentTheme.value;
      document.documentElement.lang = currentLang.value;
    }

    watch(currentLang, (lang) => {
      localStorage.setItem("otp_lang", lang);
      applyUiState();
    }, { immediate: true });

    watch(currentTheme, (theme) => {
      localStorage.setItem("icash_theme", theme);
      applyUiState();
    }, { immediate: true });

    function setStatus(message, isError = false) {
      state.status.message = message;
      state.status.type = isError ? "error" : "success";
    }

    async function parseResponse(response) {
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        return response.json();
      }
      return { detail: await response.text() };
    }

    async function handleRequestOTP() {
      if (!state.phone.trim() || state.phone.trim().length < 9) {
        setStatus(text.value.status_phone_invalid, true);
        return;
      }

      state.requestLoading = true;
      try {
        const response = await fetch("/request-otp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ phone: state.phone.trim(), lang: currentLang.value })
        });
        const data = await parseResponse(response);
        if (!response.ok) {
          setStatus(getFetchErrorMessage(data, text.value.request_failed), true);
          return;
        }

        setStatus(data.message || text.value.request_success, false);
        state.showVerify = true;
        state.requestLocked = true;
      } catch (error) {
        setStatus(text.value.status_server_error, true);
      } finally {
        state.requestLoading = false;
      }
    }

    async function handleVerifyOTP() {
      if (!/^\d{6}$/.test(state.otp.trim())) {
        setStatus(text.value.verify_prompt, true);
        return;
      }

      state.verifyLoading = true;
      try {
        const response = await fetch("/verify-otp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            phone: state.phone.trim(),
            otp: state.otp.trim(),
            lang: currentLang.value
          })
        });
        const data = await parseResponse(response);
        if (!response.ok) {
          setStatus(getFetchErrorMessage(data, text.value.verify_failed), true);
          return;
        }

        setStatus(data.message || text.value.verify_success, false);
        state.verifyLocked = true;
      } catch (error) {
        setStatus(text.value.status_server_error, true);
      } finally {
        state.verifyLoading = false;
      }
    }

    return {
      currentLang,
      currentTheme,
      text,
      state,
      handleRequestOTP,
      handleVerifyOTP
    };
  },
  template: `
    <div>
      <div class="lang-switcher">
        <div class="utility-badge">
          <div class="utility-logo">
            <img src="/assets/icash-logo-b.png" alt="iCash logo">
          </div>
          <div class="utility-copy">
            <small>iCash</small>
            <strong>{{ text.utility_title }}</strong>
          </div>
        </div>
        <div class="control-group">
          <label class="control-label">{{ text.control_language }}</label>
          <select v-model="currentLang" class="control-select">
            <option value="en">EN</option>
            <option value="kh">KH</option>
            <option value="th">TH</option>
          </select>
        </div>
        <div class="control-group">
          <label class="control-label">{{ text.control_theme }}</label>
          <select v-model="currentTheme" class="control-select">
            <option value="light">Light</option>
            <option value="dark">Dark</option>
          </select>
        </div>
      </div>

      <main class="page">
        <section class="workspace">
          <section class="brand-panel">
            <div>
              <div class="brand-top">
                <div class="brand-mark">
                  <img src="/assets/icash-logo-b.png" alt="iCash logo">
                </div>
                <div>
                  <p class="brand-eyebrow">{{ text.eyebrow }}</p>
                  <h2 class="brand-title" v-html="text.brand_title"></h2>
                </div>
              </div>

              <p class="brand-copy">{{ text.brand_copy }}</p>

              <div class="brand-steps">
                <div class="step">
                  <div class="step-number">01</div>
                  <div>
                    <strong>{{ text.step1_title }}</strong>
                    <span>{{ text.step1_desc }}</span>
                  </div>
                </div>
                <div class="step">
                  <div class="step-number">02</div>
                  <div>
                    <strong>{{ text.step2_title }}</strong>
                    <span>{{ text.step2_desc }}</span>
                  </div>
                </div>
                <div class="step">
                  <div class="step-number">03</div>
                  <div>
                    <strong>{{ text.step3_title }}</strong>
                    <span>{{ text.step3_desc }}</span>
                  </div>
                </div>
              </div>
            </div>

            <div class="brand-footer">
              <span>{{ text.footer_left }}</span>
              <span>{{ text.footer_right }}</span>
            </div>
          </section>

          <section class="auth-panel">
            <div class="auth-header">
              <span class="panel-kicker">{{ text.kicker }}</span>
              <h1>{{ text.header_h1 }}</h1>
              <p>{{ text.header_p }}</p>
            </div>

            <div id="request-section">
              <div class="field-group">
                <label>{{ text.label_phone }}</label>
                <div class="field-shell">
                  <input v-model="state.phone" type="tel" :placeholder="text.placeholder_phone" maxlength="16" autocomplete="tel" :disabled="state.requestLocked">
                </div>
              </div>
              <button type="button" @click="handleRequestOTP" :disabled="state.requestLoading || state.requestLocked">
                <span v-if="state.requestLoading" class="loader"></span>
                <span>{{ text.btn_request }}</span>
              </button>
            </div>

            <div v-if="state.showVerify" id="verify-section">
              <div class="field-group">
                <label>{{ text.label_otp }}</label>
                <div class="field-shell">
                  <input v-model="state.otp" type="text" :placeholder="text.placeholder_otp" maxlength="6" inputmode="numeric" autocomplete="one-time-code" :disabled="state.verifyLocked">
                </div>
              </div>
              <button type="button" @click="handleVerifyOTP" :disabled="state.verifyLoading || state.verifyLocked">
                <span v-if="state.verifyLoading" class="loader"></span>
                <span>{{ text.btn_verify }}</span>
              </button>
            </div>

            <div v-if="state.status.message" class="status-msg" :class="state.status.type">
              {{ state.status.message }}
            </div>
            <p class="note">{{ text.note }}</p>
          </section>
        </section>
      </main>
    </div>
  `
}).mount("#app");
