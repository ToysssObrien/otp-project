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

const translationsTh = {
  "eyebrow": "ระบบความปลอดภัย iCash",
  "brand_title": "เข้าถึง OTP<br>สำหรับ iCash",
  "brand_copy": "ยืนยันตัวตนอย่างปลอดภัยผ่าน OTP เพื่อเข้าใช้งานระบบ iCash ทั้งในโหมดทดสอบและใช้งานจริง",
  "step1_title": "กรอกหมายเลขโทรศัพท์",
  "step1_desc": "รองรับเบอร์ในกัมพูชาและรูปแบบสากล E.164",
  "step2_title": "รับ OTP",
  "step2_desc": "ระบบจะส่งรหัสผ่านผู้ให้บริการ SMS ที่ตั้งค่าไว้",
  "step3_title": "ยืนยันเพื่อเข้าใช้งาน",
  "step3_desc": "กรอกรหัส 6 หลักเพื่อยืนยันตัวตนให้เสร็จสมบูรณ์",
  "footer_left": "ประสบการณ์ลงชื่อเข้าใช้ที่ปลอดภัยสำหรับการทดสอบภายใน",
  "footer_right": "บริการ Backend OTP",
  "kicker": "การยืนยันตัวตน",
  "header_h1": "ยืนยันตัวตนเพื่อเข้าสู่ระบบ",
  "header_p": "กรอกหมายเลขโทรศัพท์เพื่อขอ OTP จากนั้นใส่รหัส 6 หลักที่ได้รับเพื่อยืนยันตัวตน",
  "label_phone": "หมายเลขโทรศัพท์",
  "control_language": "ภาษา",
  "control_theme": "ธีม",
  "placeholder_phone": "0971234567 หรือ +855971234567",
  "btn_request": "ขอ OTP",
  "label_otp": "OTP 6 หลัก",
  "placeholder_otp": "123456",
  "btn_verify": "ยืนยันรหัส",
  "note": "สำหรับการทดสอบจริง ผู้ให้บริการ SMS และสิทธิ์ในการส่งข้อความขึ้นอยู่กับการกำหนดค่าของระบบ",
  "status_phone_invalid": "กรุณากรอกหมายเลขโทรศัพท์ที่ถูกต้อง",
  "status_server_error": "ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ได้",
  "request_failed": "ไม่สามารถขอ OTP ได้",
  "request_success": "ส่ง OTP สำเร็จแล้ว",
  "verify_prompt": "กรุณากรอก OTP 6 หลัก",
  "verify_failed": "รหัส OTP ไม่ถูกต้อง",
  "verify_success": "ยืนยัน OTP สำเร็จแล้ว",
  "utility_title": "ศูนย์ OTP"
};

const translationsKh = {
  "eyebrow": "សុវត្ថិភាព iCash",
  "brand_title": "ចូលប្រើ OTP<br>សម្រាប់ iCash",
  "brand_copy": "ផ្ទៀងផ្ទាត់អត្តសញ្ញាណរបស់អ្នកដោយសុវត្ថិភាពតាមរយៈ OTP ដើម្បីចូលប្រើប្រព័ន្ធ iCash ទាំងសាកល្បង និងប្រើប្រាស់ពិតប្រាកដ",
  "step1_title": "បញ្ចូលលេខទូរស័ព្ទ",
  "step1_desc": "គាំទ្រលេខកម្ពុជា និងទម្រង់អន្តរជាតិ E.164",
  "step2_title": "ទទួល OTP",
  "step2_desc": "ប្រព័ន្ធនឹងផ្ញើកូដតាមអ្នកផ្តល់សេវា SMS ដែលបានកំណត់",
  "step3_title": "ផ្ទៀងផ្ទាត់ដើម្បីចូល",
  "step3_desc": "បញ្ចូលលេខកូដ 6 ខ្ទង់ ដើម្បីបញ្ចប់ការផ្ទៀងផ្ទាត់",
  "footer_left": "បទពិសោធន៍ចូលប្រើដែលមានសុវត្ថិភាពសម្រាប់សាកល្បងផ្ទៃក្នុង",
  "footer_right": "សេវា Backend OTP",
  "kicker": "ការផ្ទៀងផ្ទាត់",
  "header_h1": "ផ្ទៀងផ្ទាត់អត្តសញ្ញាណដើម្បីចូល",
  "header_p": "បញ្ចូលលេខទូរស័ព្ទរបស់អ្នកដើម្បីស្នើ OTP បន្ទាប់មកបញ្ចូលលេខកូដ 6 ខ្ទង់ដែលបានទទួល ដើម្បីផ្ទៀងផ្ទាត់អត្តសញ្ញាណ",
  "label_phone": "លេខទូរស័ព្ទ",
  "control_language": "ភាសា",
  "control_theme": "រចនាប័ទ្ម",
  "placeholder_phone": "0971234567 ឬ +855971234567",
  "btn_request": "ស្នើ OTP",
  "label_otp": "OTP 6 ខ្ទង់",
  "placeholder_otp": "123456",
  "btn_verify": "ផ្ទៀងផ្ទាត់កូដ",
  "note": "សម្រាប់ការសាកល្បងពិតប្រាកដ អ្នកផ្តល់សេវា SMS និងសិទ្ធិបញ្ជូន អាស្រ័យលើការកំណត់បរិស្ថានប្រព័ន្ធ",
  "status_phone_invalid": "សូមបញ្ចូលលេខទូរស័ព្ទត្រឹមត្រូវ",
  "status_server_error": "មិនអាចភ្ជាប់ទៅម៉ាស៊ីនមេបាន",
  "request_failed": "មិនអាចស្នើ OTP បាន",
  "request_success": "បានផ្ញើ OTP រួចរាល់",
  "verify_prompt": "សូមបញ្ចូល OTP 6 ខ្ទង់",
  "verify_failed": "កូដ OTP មិនត្រឹមត្រូវ",
  "verify_success": "បានផ្ទៀងផ្ទាត់ OTP ដោយជោគជ័យ",
  "utility_title": "មជ្ឈមណ្ឌល OTP"
};

const translations = {
  en: translationsEn,
  th: translationsTh,
  kh: translationsKh
};

function getFetchErrorMessage(data, fallback) {
  return data?.detail || data?.message || fallback;
}

createApp({
  setup() {
    const currentLang = ref(localStorage.getItem("otp_lang") || "th");
    const currentTheme = ref(localStorage.getItem("icash_theme") || "light");
    const text = computed(() => ({ ...translationsEn, ...(translations[currentLang.value] || {}) }));
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
          <option value="th">TH</option>
          <option value="kh">KH</option>
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
