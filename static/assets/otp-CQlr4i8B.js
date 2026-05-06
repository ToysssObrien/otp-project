import{c as f,r as d,w as p,d as _,b as g}from"./vue.esm-bundler-C-87G5uK.js";const r={en:{eyebrow:"iCash Security",brand_title:"OTP Access<br>for iCash",brand_copy:"Securely verify your identity via OTP to access iCash system with confidence, both in testing and production.",step1_title:"Enter Phone Number",step1_desc:"Supports local Cambodia numbers or international E.164 format",step2_title:"Receive OTP",step2_desc:"System will send the code via the configured SMS provider",step3_title:"Verify to Access",step3_desc:"Enter the 6-digit code to complete the verification process",footer_left:"Secure sign-in experience for internal testing",footer_right:"OTP Backend Service",kicker:"Verification",header_h1:"Verify Identity to Sign In",header_p:"Enter your phone number to request an OTP, then enter the 6-digit code received to verify your identity.",label_phone:"Phone Number",control_language:"Language",control_theme:"Theme",placeholder_phone:"0971234567 or +855971234567",btn_request:"Request OTP",label_otp:"6-digit OTP",placeholder_otp:"123456",btn_verify:"Verify Code",note:"For actual testing, the SMS provider and sending permissions depend on the system environment configuration.",status_phone_invalid:"Please enter a valid phone number",status_server_error:"Unable to connect to server",request_failed:"Unable to request OTP",request_success:"OTP was sent successfully",verify_prompt:"Please enter a 6-digit OTP",verify_failed:"Invalid OTP code",verify_success:"OTP verified successfully.",utility_title:"OTP Hub"},th:{eyebrow:"iCash Security",brand_title:"OTP Access<br>for iCash",brand_copy:"ยืนยันตัวตนอย่างปลอดภัยผ่านรหัส OTP เพื่อเข้าใช้งานระบบ iCash ได้อย่างมั่นใจ ทั้งในขั้นตอนทดสอบและการเชื่อมต่อใช้งานจริง",step1_title:"กรอกเบอร์โทรศัพท์",step1_desc:"รองรับเบอร์กัมพูชาแบบ local หรือรูปแบบสากล E.164",step2_title:"รับรหัส OTP",step2_desc:"ระบบจะส่งรหัสผ่านผู้ให้บริการ SMS ที่ตั้งค่าไว้ในระบบ",step3_title:"ยืนยันเพื่อเข้าใช้งาน",step3_desc:"กรอกรหัส 6 หลักเพื่อปิดขั้นตอนยืนยันตัวตนให้สมบูรณ์",footer_left:"ประสบการณ์เข้าสู่ระบบอย่างปลอดภัยสำหรับการทดสอบภายใน",footer_right:"OTP Backend Service",kicker:"Verification",header_h1:"ยืนยันตัวตนเพื่อเข้าสู่ระบบ",header_p:"กรอกเบอร์โทรศัพท์เพื่อขอรหัส OTP จากนั้นกรอกรหัส 6 หลักที่ได้รับเพื่อยืนยันตัวตน",label_phone:"เบอร์โทรศัพท์",control_language:"ภาษา",control_theme:"ธีม",placeholder_phone:"0971234567 หรือ +855971234567",btn_request:"ขอรหัส OTP",label_otp:"รหัส OTP 6 หลัก",placeholder_otp:"123456",btn_verify:"ยืนยันรหัส",note:"สำหรับการทดสอบจริง ผู้ให้บริการ SMS และสิทธิ์การส่งจะขึ้นอยู่กับ environment ที่ตั้งค่าไว้บนระบบ",status_phone_invalid:"กรุณากรอกเบอร์โทรศัพท์ให้ถูกต้อง",status_server_error:"ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ได้",request_failed:"เกิดข้อผิดพลาดในการขอ OTP",request_success:"ส่งรหัส OTP สำเร็จ",verify_prompt:"กรุณากรอกรหัส OTP 6 หลัก",verify_failed:"รหัส OTP ไม่ถูกต้อง",verify_success:"ยืนยันรหัส OTP สำเร็จ",utility_title:"OTP Hub"},kh:{}};r.kh={...r.en};function u(s,n){return s?.detail||s?.message||n}f({setup(){const s=d(localStorage.getItem("otp_lang")||"th"),n=d(localStorage.getItem("icash_theme")||"light"),a=_(()=>r[s.value]||r.en),t=g({phone:"",otp:"",requestLocked:!1,verifyLocked:!1,requestLoading:!1,verifyLoading:!1,showVerify:!1,status:{message:"",type:"success"}});function l(){document.documentElement.dataset.theme=n.value,document.documentElement.lang=s.value}p(s,e=>{localStorage.setItem("otp_lang",e),l()},{immediate:!0}),p(n,e=>{localStorage.setItem("icash_theme",e),l()},{immediate:!0});function i(e,o=!1){t.status.message=e,t.status.type=o?"error":"success"}async function c(e){return(e.headers.get("content-type")||"").includes("application/json")?e.json():{detail:await e.text()}}async function v(){if(!t.phone.trim()||t.phone.trim().length<9){i(a.value.status_phone_invalid,!0);return}t.requestLoading=!0;try{const e=await fetch("/request-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({phone:t.phone.trim(),lang:s.value})}),o=await c(e);if(!e.ok){i(u(o,a.value.request_failed),!0);return}i(o.message||a.value.request_success,!1),t.showVerify=!0,t.requestLocked=!0}catch{i(a.value.status_server_error,!0)}finally{t.requestLoading=!1}}async function h(){if(!/^\d{6}$/.test(t.otp.trim())){i(a.value.verify_prompt,!0);return}t.verifyLoading=!0;try{const e=await fetch("/verify-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({phone:t.phone.trim(),otp:t.otp.trim(),lang:s.value})}),o=await c(e);if(!e.ok){i(u(o,a.value.verify_failed),!0);return}i(o.message||a.value.verify_success,!1),t.verifyLocked=!0}catch{i(a.value.status_server_error,!0)}finally{t.verifyLoading=!1}}return{currentLang:s,currentTheme:n,text:a,state:t,handleRequestOTP:v,handleVerifyOTP:h}},template:`
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
  `}).mount("#app");
