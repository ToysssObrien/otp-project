import { createApp, reactive, ref, computed, watch, onMounted, onBeforeUnmount, nextTick } from "vue/dist/vue.esm-bundler.js";
import * as XLSX from "xlsx";
import "./admin.css";

const translations = {
  en: {
    brand_kicker: "iCash Verify",
    brand_subtitle: "Support workspace for dashboard, phone verification, and customer records.",
    login_title: "Admin Console",
    login_desc: "Management interface for OTP support and customer data.",
    login_panel_h2: "Admin Login",
    label_username: "Username",
    label_password: "Password",
    btn_login: "Login",
    control_language: "Language",
    control_theme: "Theme",
    nav_workspace: "Workspace",
    nav_dashboard: "Dashboard",
    nav_verify_phone: "Verify Phone",
    nav_customers: "Customers",
    btn_refresh: "Refresh Data",
    btn_logout: "Logout",
    dashboard_title: "Dashboard",
    dashboard_desc: "System overview and provider activity.",
    verify_phone_title: "Verify Phone",
    verify_phone_copy: "Use this page to enter customer details, save them, send OTP, and verify.",
    customers_title: "Customers",
    customers_copy: "This page is for simple viewing, import, export, and template download.",
    recent_activity: "Recent Activity",
    recent_activity_copy: "Latest OTP request and verification events.",
    provider_status: "Provider Status",
    provider_status_copy: "Health and average latency by provider.",
    status_checking: "Checking system status...",
    status_normal: "System Normal",
    status_warning: "Needs Attention",
    label_phone: "Phone Number",
    label_otp_digit: "6-Digit OTP",
    expires_in: "Expires in",
    sent_to: "Sent to",
    verify_step_ready: "Verification step is ready.",
    btn_send_otp: "Send OTP",
    btn_verify_otp: "Verify OTP",
    btn_reset: "Reset",
    label_customer_id: "Customer ID",
    label_customer_name: "Name",
    label_customer_phone: "Phone Number",
    label_customer_otp: "OTP",
    btn_save_customer: "Save Customer",
    btn_import_excel: "Import Excel/CSV",
    btn_export_excel: "Export Excel",
    btn_export_csv: "Export CSV",
    btn_download_template: "Download Template",
    customer_table_title: "Customer Records",
    customer_table_copy: "Imported or saved customer data will appear here.",
    search_placeholder: "Search by ID, name, phone, or OTP",
    table_empty: "No customer records yet.",
    m_req: "Requests",
    m_success: "Success",
    m_fail: "Failed Verify",
    m_blocked: "Blocked",
    login_invalid: "Invalid login credentials.",
    verify_phone_required: "Please enter a phone number before requesting OTP.",
    verify_otp_required: "Please enter a 6-digit OTP.",
    customers_saved: "Customer records saved.",
    customers_loaded: "Customer records loaded.",
    customers_imported: "Customer file imported successfully.",
    customers_exported: "Customer file exported.",
    customer_form_invalid: "Please fill Customer ID, Name, and Phone Number.",
    file_invalid: "Unsupported file. Please use .xlsx, .xls, or .csv.",
    save_failed: "Unable to save customer records.",
    request_failed: "Unable to request OTP.",
    provider_unknown: "Unknown provider status",
    loading_workspace: "Loading workspace...",
    template_tagline_1: "Cloud-ready OTP support",
    template_tagline_2: "Dashboard + Verify + Customers",
    utility_title: "Admin Hub"
  },
  th: {
    brand_kicker: "iCash Verify",
    brand_subtitle: "พื้นที่ทำงานสำหรับแดชบอร์ด ยืนยันเบอร์โทร และจัดการข้อมูลลูกค้า",
    login_title: "OTP Admin",
    login_desc: "หน้าจัดการสำหรับงาน OTP และข้อมูลลูกค้า",
    login_panel_h2: "เข้าสู่ระบบแอดมิน",
    label_username: "ชื่อผู้ใช้",
    label_password: "รหัสผ่าน",
    btn_login: "เข้าสู่ระบบ",
    control_language: "ภาษา",
    control_theme: "ธีม",
    nav_workspace: "เมนูทำงาน",
    nav_dashboard: "แดชบอร์ด",
    nav_verify_phone: "Verify Phone",
    nav_customers: "ลูกค้า",
    btn_refresh: "รีเฟรชข้อมูล",
    btn_logout: "ออกจากระบบ",
    dashboard_title: "แดชบอร์ด",
    dashboard_desc: "ภาพรวมระบบและสถานะของผู้ให้บริการ OTP",
    verify_phone_title: "ยืนยันเบอร์โทร",
    verify_phone_copy: "กรอกข้อมูลลูกค้า บันทึก ส่ง OTP และยืนยันได้ในหน้าเดียว",
    customers_title: "ข้อมูลลูกค้า",
    customers_copy: "ใช้หน้านี้สำหรับดูข้อมูล ค้นหา import/export และดาวน์โหลดเทมเพลต",
    recent_activity: "กิจกรรมล่าสุด",
    recent_activity_copy: "เหตุการณ์ล่าสุดของการขอและยืนยัน OTP",
    provider_status: "สถานะผู้ให้บริการ",
    provider_status_copy: "สุขภาพระบบและค่า latency เฉลี่ยของแต่ละ provider",
    status_checking: "กำลังตรวจสอบสถานะระบบ...",
    status_normal: "ระบบปกติ",
    status_warning: "ต้องตรวจสอบเพิ่ม",
    label_phone: "เบอร์โทรศัพท์",
    label_otp_digit: "รหัส OTP 6 หลัก",
    expires_in: "หมดอายุใน",
    sent_to: "ส่งไปที่",
    verify_step_ready: "พร้อมสำหรับขั้นตอนยืนยันแล้ว",
    btn_send_otp: "ส่ง OTP",
    btn_verify_otp: "ยืนยัน OTP",
    btn_reset: "รีเซ็ต",
    label_customer_id: "รหัสลูกค้า",
    label_customer_name: "ชื่อลูกค้า",
    label_customer_phone: "เบอร์โทรศัพท์",
    label_customer_otp: "OTP",
    btn_save_customer: "บันทึกลูกค้า",
    btn_import_excel: "นำเข้า Excel/CSV",
    btn_export_excel: "ส่งออก Excel",
    btn_export_csv: "ส่งออก CSV",
    btn_download_template: "ดาวน์โหลดเทมเพลต",
    customer_table_title: "รายการลูกค้า",
    customer_table_copy: "ข้อมูลที่ import หรือบันทึกไว้จะแสดงที่นี่",
    search_placeholder: "ค้นหาด้วยรหัส ชื่อ เบอร์ หรือ OTP",
    table_empty: "ยังไม่มีข้อมูลลูกค้า",
    m_req: "จำนวนคำขอ",
    m_success: "ยืนยันสำเร็จ",
    m_fail: "ยืนยันไม่สำเร็จ",
    m_blocked: "ถูกบล็อก",
    login_invalid: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
    verify_phone_required: "กรุณากรอกเบอร์โทรศัพท์ก่อนส่ง OTP",
    verify_otp_required: "กรุณากรอกรหัส OTP 6 หลัก",
    customers_saved: "บันทึกข้อมูลลูกค้าแล้ว",
    customers_loaded: "โหลดข้อมูลลูกค้าแล้ว",
    customers_imported: "นำเข้าข้อมูลลูกค้าสำเร็จ",
    customers_exported: "ส่งออกไฟล์ลูกค้าสำเร็จ",
    customer_form_invalid: "กรุณากรอกรหัสลูกค้า ชื่อ และเบอร์โทรศัพท์ให้ครบ",
    file_invalid: "ไฟล์ไม่รองรับ กรุณาใช้ .xlsx, .xls หรือ .csv",
    save_failed: "ไม่สามารถบันทึกข้อมูลลูกค้าได้",
    request_failed: "ไม่สามารถส่งคำขอ OTP ได้",
    provider_unknown: "ไม่ทราบสถานะ provider",
    loading_workspace: "กำลังโหลดหน้าจอ...",
    template_tagline_1: "รองรับงาน OTP บนคลาวด์",
    template_tagline_2: "Dashboard + Verify + Customers",
    utility_title: "Admin Hub"
  },
  kh: {
    brand_kicker: "iCash Verify",
    brand_subtitle: "តំបន់ការងារសម្រាប់ផ្ទាំងគ្រប់គ្រង ការផ្ទៀងផ្ទាត់លេខទូរស័ព្ទ និងកំណត់ត្រាអតិថិជន។",
    login_title: "ផ្ទាំងគ្រប់គ្រង",
    login_desc: "ចំណុចប្រទាក់គ្រប់គ្រងសម្រាប់ជំនួយ OTP និងទិន្នន័យអតិថិជន។",
    login_panel_h2: "ចូលប្រព័ន្ធ Admin",
    label_username: "ឈ្មោះអ្នកប្រើ",
    label_password: "ពាក្យសម្ងាត់",
    btn_login: "ចូលប្រព័ន្ធ",
    control_language: "ភាសា",
    control_theme: "រូបរាង",
    nav_workspace: "តំបន់ការងារ",
    nav_dashboard: "ផ្ទាំងគ្រប់គ្រង",
    nav_verify_phone: "ផ្ទៀងផ្ទាត់លេខ",
    nav_customers: "អតិថិជន",
    btn_refresh: "ធ្វើឱ្យទិន្នន័យថ្មី",
    btn_logout: "ចាកចេញ",
    dashboard_title: "ផ្ទាំងគ្រប់គ្រង",
    dashboard_desc: "ទិដ្ឋភាពរួមប្រព័ន្ធ និងសកម្មភាពអ្នកផ្តល់សេវា។",
    verify_phone_title: "ផ្ទៀងផ្ទាត់លេខ",
    verify_phone_copy: "ប្រើទំព័រនេះដើម្បីបញ្ចូលព័ត៌មានអតិថិជន រក្សាទុក ផ្ញើ OTP និងផ្ទៀងផ្ទាត់។",
    customers_title: "អតិថិជន",
    customers_copy: "ទំព័រនេះសម្រាប់មើល យកចូល យកចេញ និងទាញយកគំរូសាមញ្ញ។",
    recent_activity: "សកម្មភាពថ្មីៗ",
    recent_activity_copy: "ព្រឹត្តិការណ៍ស្នើ OTP និងផ្ទៀងផ្ទាត់ចុងក្រោយបំផុត។",
    provider_status: "ស្ថានភាពអ្នកផ្តល់សេវា",
    provider_status_copy: "សុខភាព និង latency មធ្យមតាម provider នីមួយៗ។",
    status_checking: "កំពុងពិនិត្យស្ថានភាពប្រព័ន្ធ...",
    status_normal: "ប្រព័ន្ធដំណើរការល្អ",
    status_warning: "ត្រូវការការយកចិត្តទុកដាក់",
    label_phone: "លេខទូរស័ព្ទ",
    label_otp_digit: "OTP 6 ខ្ទង់",
    expires_in: "ផុតកំណត់ក្នុង",
    sent_to: "បានផ្ញើទៅកាន់",
    verify_step_ready: "ជំហានផ្ទៀងផ្ទាត់រួចរាល់ហើយ។",
    btn_send_otp: "ផ្ញើ OTP",
    btn_verify_otp: "ផ្ទៀងផ្ទាត់ OTP",
    btn_reset: "កំណត់ឡើងវិញ",
    label_customer_id: "លេខសម្គាល់អតិថិជន",
    label_customer_name: "ឈ្មោះ",
    label_customer_phone: "លេខទូរស័ព្ទ",
    label_customer_otp: "OTP",
    btn_save_customer: "រក្សាទុកអតិថិជន",
    btn_import_excel: "យកចូល Excel/CSV",
    btn_export_excel: "នាំចេញ Excel",
    btn_export_csv: "នាំចេញ CSV",
    btn_download_template: "ទាញយកគំរូ",
    customer_table_title: "កំណត់ត្រាអតិថិជន",
    customer_table_copy: "ទិន្នន័យអតិថិជនដែលបានយកចូល ឬរក្សាទុក នឹងបង្ហាញនៅទីនេះ។",
    search_placeholder: "ស្វែងរកតាមលេខសម្គាល់ ឈ្មោះ លេខទូរស័ព្ទ ឬ OTP",
    table_empty: "មិនទាន់មានកំណត់ត្រាអតិថិជនឡើយ។",
    m_req: "សំណើ",
    m_success: "ជោគជ័យ",
    m_fail: "ផ្ទៀងផ្ទាត់បរាជ័យ",
    m_blocked: "ត្រូវបានបិទ",
    login_invalid: "ឈ្មោះអ្នកប្រើ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ។",
    verify_phone_required: "សូមបញ្ចូលលេខទូរស័ព្ទមុននឹងស្នើ OTP។",
    verify_otp_required: "សូមបញ្ចូល OTP 6 ខ្ទង់។",
    customers_saved: "បានរក្សាទុកកំណត់ត្រាអតិថិជន។",
    customers_loaded: "បានផ្ទុកកំណត់ត្រាអតិថិជន។",
    customers_imported: "បានយកចូលឯកសារអតិថិជនដោយជោគជ័យ។",
    customers_exported: "បាននាំចេញឯកសារអតិថិជន។",
    customer_form_invalid: "សូមបំពេញលេខសម្គាល់អតិថិជន ឈ្មោះ និងលេខទូរស័ព្ទឱ្យគ្រប់។",
    file_invalid: "ឯកសារមិនគាំទ្រ។ សូមប្រើ .xlsx, .xls ឬ .csv ។",
    save_failed: "មិនអាចរក្សាទុកកំណត់ត្រាអតិថិជនបានទេ។",
    request_failed: "មិនអាចស្នើ OTP បានទេ។",
    provider_unknown: "មិនស្គាល់ស្ថានភាពអ្នកផ្តល់សេវា",
    loading_workspace: "កំពុងផ្ទុកតំបន់ការងារ...",
    template_tagline_1: "ជំនួយ OTP ត្រៀមសម្រាប់ Cloud",
    template_tagline_2: "ផ្ទាំងគ្រប់គ្រង + ផ្ទៀងផ្ទាត់ + អតិថិជន",
    utility_title: "ផ្ទាំង Admin"
  }
};

const sectionConfig = {
  dashboard: { kicker: "ផ្ទាំងគ្រប់គ្រង", titleKey: "dashboard_title", descKey: "dashboard_desc" },
  "verify-phone": { kicker: "ផ្ទៀងផ្ទាត់លេខ", titleKey: "verify_phone_title", descKey: "verify_phone_copy" },
  customers: { kicker: "អតិថិជន", titleKey: "customers_title", descKey: "customers_copy" }
};

function formatDuration(seconds) {
  const safeSeconds = Math.max(Number(seconds) || 0, 0);
  const minutes = Math.floor(safeSeconds / 60);
  const remainder = safeSeconds % 60;
  return `${minutes}:${String(remainder).padStart(2, "0")}`;
}

function normalizeImportedHeaders(row) {
  const normalized = {};
  Object.entries(row || {}).forEach(([key, value]) => {
    const cleanKey = String(key || "").replace(/\s+/g, "").replace(/_/g, "").toLowerCase();
    normalized[cleanKey] = value;
  });
  return normalized;
}

function convertImportedRows(rows) {
  return rows
    .map((row) => normalizeImportedHeaders(row))
    .map((row) => ({
      id: String(row.id ?? row.customerid ?? row.customer ?? "").trim(),
      name: String(row.name ?? row.customername ?? "").trim(),
      phone_number: String(row.phonenumber ?? row.phone ?? row.mobilenumber ?? "").trim(),
      otp: String(row.otp ?? "").trim()
    }))
    .filter((row) => row.id && row.name && row.phone_number);
}

function parseCsvLine(line) {
  const values = [];
  let current = "";
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    const nextChar = line[index + 1];

    if (char === "\"" && inQuotes && nextChar === "\"") {
      current += "\"";
      index += 1;
      continue;
    }

    if (char === "\"") {
      inQuotes = !inQuotes;
      continue;
    }

    if (char === "," && !inQuotes) {
      values.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  values.push(current);
  return values;
}

function parseCsvText(text) {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").filter((line) => line.trim());
  if (!lines.length) {
    return [];
  }

  const headers = parseCsvLine(lines[0]);
  return lines.slice(1).map((line) => {
    const values = parseCsvLine(line);
    const row = {};
    headers.forEach((header, index) => {
      row[header] = values[index] ?? "";
    });
    return row;
  });
}

function escapeCsvValue(value) {
  const text = String(value ?? "");
  if (/[",\n]/.test(text)) {
    return `"${text.replace(/"/g, "\"\"")}"`;
  }
  return text;
}

function downloadBlob(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function getFetchErrorMessage(data, fallback) {
  return data?.detail || data?.message || fallback;
}

createApp({
  setup() {
    const currentLang = ref(localStorage.getItem("otp_lang") || "th");
    const currentTheme = ref(localStorage.getItem("icash_theme") || "dark");
    const customerFileInput = ref(null);
    const refreshTimer = ref(null);
    const countdownTimer = ref(null);
    const popupTimer = ref(null);

    const state = reactive({
      authResolved: false,
      authenticated: false,
      loading: false,
      verifyBusy: false,
      activeSection: "dashboard",
      metrics: null,
      customers: [],
      editingCustomerId: null,
      verifyStepReady: false,
      verifyCountdownRemaining: 0,
      searchQuery: "",
      loginForm: {
        username: "",
        password: ""
      },
      verifyForm: {
        id: "",
        name: "",
        phone_number: "",
        otp: ""
      },
      verifyPopup: {
        open: false,
        mode: "loading",
        message: ""
      },
      status: {
        login: { message: "", messageKey: "", messageParams: {}, type: "error" },
        verify: { message: "", messageKey: "", messageParams: {}, type: "success" },
        customers: { message: "", messageKey: "", messageParams: {}, type: "success" }
      }
    });

    const text = computed(() => translations[currentLang.value] || translations.en);
    const summaryCards = computed(() => {
      const summary = state.metrics?.summary || {};
      return [
        { label: text.value.m_req, value: summary.request_total ?? 0 },
        { label: text.value.m_success, value: summary.verify_success_total ?? 0 },
        { label: text.value.m_fail, value: summary.verify_failed_total ?? 0 },
        { label: text.value.m_blocked, value: summary.request_blocked_total ?? 0 }
      ];
    });
    const providers = computed(() => Array.isArray(state.metrics?.providers) ? state.metrics.providers : []);
    const recentEvents = computed(() => Array.isArray(state.metrics?.recent_events) ? state.metrics.recent_events.slice(0, 8) : []);
    const currentSectionMeta = computed(() => sectionConfig[state.activeSection] || sectionConfig.dashboard);
    const systemStatusText = computed(() => {
      const allHealthy = providers.value.length > 0 && providers.value.every((provider) => provider.health === "healthy");
      return allHealthy ? text.value.status_normal : text.value.status_warning;
    });
    const filteredCustomers = computed(() => {
      const query = state.searchQuery.trim().toLowerCase();
      if (!query) {
        return state.customers;
      }
      return state.customers.filter((customer) =>
        [customer.id, customer.name, customer.phone_number, customer.otp]
          .some((value) => String(value || "").toLowerCase().includes(query))
      );
    });
    const verifyCountdownText = computed(() => state.verifyStepReady ? formatDuration(state.verifyCountdownRemaining) : "-");

    function applyUiState() {
      document.documentElement.lang = currentLang.value;
      document.documentElement.dataset.theme = currentTheme.value;
    }

    watch(currentLang, (lang) => {
      localStorage.setItem("otp_lang", lang);
      applyUiState();
    }, { immediate: true });

    watch(currentTheme, (theme) => {
      localStorage.setItem("icash_theme", theme);
      applyUiState();
    }, { immediate: true });

    function setStatus(scope, message, type = "success") {
      state.status[scope] = { message, messageKey: "", messageParams: {}, type };
    }

    function setLocalizedStatus(scope, messageKey, type = "success", messageParams = {}) {
      state.status[scope] = { message: "", messageKey, messageParams, type };
    }

    function clearStatus(scope) {
      state.status[scope] = { message: "", messageKey: "", messageParams: {}, type: "success" };
    }

    function clearVerifyPopupTimer() {
      if (popupTimer.value) {
        window.clearTimeout(popupTimer.value);
        popupTimer.value = null;
      }
    }

    function showVerifyPopup(mode, message) {
      clearVerifyPopupTimer();
      state.verifyPopup.open = true;
      state.verifyPopup.mode = mode;
      state.verifyPopup.message = message;
    }

    function hideVerifyPopup() {
      clearVerifyPopupTimer();
      state.verifyPopup.open = false;
      state.verifyPopup.mode = "loading";
      state.verifyPopup.message = "";
    }

    function showVerifySuccessPopup(message) {
      showVerifyPopup("success", message);
      popupTimer.value = window.setTimeout(() => {
        hideVerifyPopup();
      }, 1800);
    }

    function getStatusMessage(scope) {
      const status = state.status[scope] || {};
      if (status.messageKey) {
        if (status.messageKey === "sent_to") {
          return status.messageParams?.phone
            ? `${text.value.sent_to}: ${status.messageParams.phone}`
            : text.value.sent_to;
        }
        return text.value[status.messageKey] || status.message || "";
      }
      return status.message || "";
    }

    function setActiveSection(sectionName, syncHash = true) {
      const nextSection = sectionConfig[sectionName] ? sectionName : "dashboard";
      state.activeSection = nextSection;
      if (syncHash) {
        window.location.hash = nextSection === "dashboard" ? "" : nextSection;
      }
    }

    function syncSectionFromHash() {
      setActiveSection(window.location.hash.replace("#", "") || "dashboard", false);
    }

    function stopCountdown() {
      if (countdownTimer.value) {
        window.clearInterval(countdownTimer.value);
        countdownTimer.value = null;
      }
    }

    function startVerifyCountdown(seconds) {
      state.verifyCountdownRemaining = Number(seconds) || 0;
      stopCountdown();
      countdownTimer.value = window.setInterval(() => {
        state.verifyCountdownRemaining -= 1;
        if (state.verifyCountdownRemaining <= 0) {
          state.verifyCountdownRemaining = 0;
          stopCountdown();
        }
      }, 1000);
    }

    function resetVerifyForm() {
      state.verifyForm.id = "";
      state.verifyForm.name = "";
      state.verifyForm.phone_number = "";
      state.verifyForm.otp = "";
      state.verifyStepReady = false;
      state.verifyBusy = false;
      state.editingCustomerId = null;
      clearStatus("verify");
      hideVerifyPopup();
      stopCountdown();
    }

    function fillVerifyCustomerForm(customer) {
      state.verifyForm.id = customer.id || "";
      state.verifyForm.name = customer.name || "";
      state.verifyForm.phone_number = customer.phone_number || "";
      state.verifyForm.otp = customer.otp || "";
      state.editingCustomerId = customer.id || null;
    }

    async function parseResponse(response) {
      const contentType = response.headers.get("content-type") || "";
      if (contentType.includes("application/json")) {
        return response.json();
      }
      return { detail: await response.text() };
    }

    async function persistCustomers(successMessageKey = "", target = "customers") {
      const response = await fetch("/admin/customers", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ customers: state.customers })
      });
      const data = await parseResponse(response);
      if (!response.ok) {
        throw new Error(getFetchErrorMessage(data, text.value.save_failed));
      }
      state.customers = Array.isArray(data.customers) ? data.customers : [];
      if (successMessageKey) {
        setLocalizedStatus(target, successMessageKey, "success");
      }
    }

    async function loadCustomers(showLoadedStatus = false) {
      const response = await fetch("/admin/customers");
      const data = await parseResponse(response);
      if (!response.ok) {
        throw new Error(getFetchErrorMessage(data, text.value.save_failed));
      }
      state.customers = Array.isArray(data.customers) ? data.customers : [];
      if (showLoadedStatus) {
        setLocalizedStatus("customers", "customers_loaded", "success");
      }
    }

    async function refreshData() {
      const response = await fetch("/admin/metrics");
      const data = await parseResponse(response);
      if (!response.ok) {
        throw new Error(getFetchErrorMessage(data, "Unable to load metrics."));
      }
      state.metrics = data;
    }

    async function loadAdminData() {
      await Promise.all([refreshData(), loadCustomers()]);
    }

    function startRefreshTimer() {
      if (refreshTimer.value) {
        return;
      }
      refreshTimer.value = window.setInterval(async () => {
        try {
          await refreshData();
        } catch (error) {
          console.error(error);
        }
      }, 15000);
    }

    function stopRefreshTimer() {
      if (refreshTimer.value) {
        window.clearInterval(refreshTimer.value);
        refreshTimer.value = null;
      }
    }

    async function checkAuth() {
      try {
        const response = await fetch("/admin/session");
        const data = await parseResponse(response);
        state.authenticated = Boolean(data.authenticated);
        state.authResolved = true;
        if (state.authenticated) {
          syncSectionFromHash();
          await loadAdminData();
          startRefreshTimer();
        }
      } catch (error) {
        state.authResolved = true;
        state.authenticated = false;
      }
    }

    async function handleLogin() {
      clearStatus("login");
      const response = await fetch("/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(state.loginForm)
      });
      if (response.ok) {
        state.loginForm.password = "";
        state.authResolved = false;
        await checkAuth();
        return;
      }
      setLocalizedStatus("login", "login_invalid", "error");
    }

    async function handleLogout() {
      await fetch("/admin/logout", { method: "POST" });
      state.authenticated = false;
      state.authResolved = true;
      stopRefreshTimer();
      resetVerifyForm();
    }

    async function saveVerifyCustomerRecord({ showSuccess = true, requireComplete = true } = {}) {
      const formValues = {
        id: state.verifyForm.id.trim(),
        name: state.verifyForm.name.trim(),
        phone_number: state.verifyForm.phone_number.trim(),
        otp: state.verifyForm.otp.trim()
      };
      const hasCoreFields = formValues.id && formValues.name && formValues.phone_number;
      if (!hasCoreFields) {
        if (requireComplete) {
          setLocalizedStatus("verify", "customer_form_invalid", "error");
        }
        return null;
      }

      const lookupId = state.editingCustomerId || formValues.id;
      const existingIndex = state.customers.findIndex((customer) => customer.id === lookupId);
      if (existingIndex >= 0) {
        state.customers.splice(existingIndex, 1, formValues);
      } else {
        state.customers.unshift(formValues);
      }

      await persistCustomers(showSuccess ? "customers_saved" : "", showSuccess ? "verify" : "");
      const persistedCustomer = state.customers.find((customer) => customer.id === formValues.id) || formValues;
      fillVerifyCustomerForm(persistedCustomer);
      return persistedCustomer;
    }

    async function requestStaffOtp() {
      clearStatus("verify");
      if (!state.verifyForm.phone_number.trim()) {
        setLocalizedStatus("verify", "verify_phone_required", "error");
        return;
      }

      try {
        const response = await fetch("/api/request-otp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ phone: state.verifyForm.phone_number.trim(), lang: currentLang.value })
        });
        const data = await parseResponse(response);
        if (!response.ok) {
          setStatus("verify", getFetchErrorMessage(data, text.value.request_failed), "error");
          return;
        }

        state.verifyStepReady = true;
        startVerifyCountdown(data.expires_in || 0);
        setLocalizedStatus("verify", "sent_to", "success", { phone: state.verifyForm.phone_number.trim() });
      } catch (error) {
        setStatus("verify", error?.message || text.value.request_failed, "error");
      }
    }

    async function verifyStaffOtp() {
      clearStatus("verify");
      const phone = state.verifyForm.phone_number.trim();
      const otp = state.verifyForm.otp.trim();

      if (!/^\d{6}$/.test(otp)) {
        setLocalizedStatus("verify", "verify_otp_required", "error");
        return;
      }

      state.verifyBusy = true;
      showVerifyPopup("loading", "Verifying OTP...");

      try {
        const response = await fetch("/api/verify-otp", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ phone, otp, lang: currentLang.value })
        });
        const data = await parseResponse(response);
        if (response.ok) {
          setLocalizedStatus("verify", "verify_success", "success");
          showVerifySuccessPopup("OTP verified successfully.");
          await nextTick();
          try {
            await saveVerifyCustomerRecord({ showSuccess: false, requireComplete: false });
            await refreshData();
          } catch (error) {
            console.error(error);
          }
        } else {
          hideVerifyPopup();
          setStatus("verify", getFetchErrorMessage(data, "-"), "error");
        }
      } catch (error) {
        hideVerifyPopup();
        setStatus("verify", error?.message || "-", "error");
      } finally {
        state.verifyBusy = false;
      }
    }

    function triggerCustomerImport() {
      customerFileInput.value?.click();
    }

    async function importCustomerFile(event) {
      const file = event.target.files?.[0];
      if (!file) {
        return;
      }

      try {
        const extension = file.name.split(".").pop()?.toLowerCase();
        if (!["xlsx", "xls", "csv"].includes(extension || "")) {
          setLocalizedStatus("customers", "file_invalid", "error");
          return;
        }

        let rawRows = [];
        if (extension === "csv") {
          rawRows = parseCsvText(await file.text());
        } else {
          const buffer = await file.arrayBuffer();
          const workbook = XLSX.read(buffer, { type: "array" });
          const worksheet = workbook.Sheets[workbook.SheetNames[0]];
          rawRows = XLSX.utils.sheet_to_json(worksheet, { defval: "" });
        }

        state.customers = convertImportedRows(rawRows);
        await persistCustomers("customers_imported", "customers");
      } catch (error) {
        setStatus("customers", error.message || text.value.file_invalid, "error");
      } finally {
        event.target.value = "";
      }
    }

    function exportCustomers(format) {
      const rows = state.customers.map((customer) => ({
        ID: customer.id,
        Name: customer.name,
        PhoneNumber: customer.phone_number,
        OTP: customer.otp || ""
      }));

      if (format === "csv") {
        const headers = ["ID", "Name", "PhoneNumber", "OTP"];
        const csvContent = [
          headers.join(","),
          ...rows.map((row) => headers.map((header) => escapeCsvValue(row[header])).join(","))
        ].join("\n");
        downloadBlob("customers.csv", csvContent, "text/csv;charset=utf-8;");
        setLocalizedStatus("customers", "customers_exported", "success");
        return;
      }

      const worksheet = XLSX.utils.json_to_sheet(rows);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, "Customers");
      XLSX.writeFile(workbook, "customers.xlsx", { bookType: "xlsx" });
      setLocalizedStatus("customers", "customers_exported", "success");
    }

    function downloadTemplate() {
      window.location.href = "/customer-import-template.xlsx";
    }

    onMounted(() => {
      window.addEventListener("hashchange", syncSectionFromHash);
      checkAuth().catch((error) => console.error(error));
    });

    onBeforeUnmount(() => {
      window.removeEventListener("hashchange", syncSectionFromHash);
      stopRefreshTimer();
      stopCountdown();
      clearVerifyPopupTimer();
    });

    return {
      state,
      text,
      currentLang,
      currentTheme,
      customerFileInput,
      summaryCards,
      providers,
      recentEvents,
      currentSectionMeta,
      systemStatusText,
      filteredCustomers,
      verifyCountdownText,
      setActiveSection,
      handleLogin,
      handleLogout,
      requestStaffOtp,
      verifyStaffOtp,
      resetVerifyForm,
      triggerCustomerImport,
      importCustomerFile,
      exportCustomers,
      downloadTemplate,
      saveVerifyCustomerRecord,
      refreshData,
      getStatusMessage
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

      <div v-if="!state.authResolved" class="login-view">
        <div class="glass login-panel">
          <h2>{{ text.loading_workspace }}</h2>
        </div>
      </div>

      <div v-else-if="!state.authenticated" class="login-view">
        <div class="login-shell">
          <div class="login-brand glass">
            <div class="brand-cloud">
              <div class="brand-mark">
                <img src="/assets/icash-logo-b.png" alt="iCash logo">
              </div>
              <div>
                <span class="brand-kicker">{{ text.brand_kicker }}</span>
                <h1>{{ text.login_title }}</h1>
                <p>{{ text.login_desc }}</p>
              </div>
            </div>
            <div class="login-brand-footer">
              <span>{{ text.template_tagline_1 }}</span>
              <span>{{ text.template_tagline_2 }}</span>
            </div>
          </div>

          <div class="login-panel">
            <h2>{{ text.login_panel_h2 }}</h2>
            <form @submit.prevent="handleLogin">
              <div class="field">
                <label>{{ text.label_username }}</label>
                <input v-model="state.loginForm.username" type="text" required>
              </div>
              <div class="field">
                <label>{{ text.label_password }}</label>
                <input v-model="state.loginForm.password" type="password" required>
              </div>
              <button type="submit" class="button">{{ text.btn_login }}</button>
              <div v-if="getStatusMessage('login')" class="status-panel" :class="state.status.login.type">
                {{ getStatusMessage('login') }}
              </div>
            </form>
          </div>
        </div>
      </div>

      <div v-else class="page">
        <div class="shell">
          <aside class="sidebar glass">
            <div class="sidebar-brand">
              <div class="sidebar-mark">
                <img src="/assets/icash-logo-b.png" alt="iCash logo">
              </div>
              <div>
                <span class="brand-kicker">{{ text.brand_kicker }}</span>
                <h1>OTP Admin</h1>
                <p>{{ text.brand_subtitle }}</p>
              </div>
            </div>

            <div class="sidebar-group">
              <h3>{{ text.nav_workspace }}</h3>
              <div class="nav-list">
                <button class="nav-button" :class="{ active: state.activeSection === 'dashboard' }" @click="setActiveSection('dashboard')">{{ text.nav_dashboard }}</button>
                <button class="nav-button" :class="{ active: state.activeSection === 'verify-phone' }" @click="setActiveSection('verify-phone')">{{ text.nav_verify_phone }}</button>
                <button class="nav-button" :class="{ active: state.activeSection === 'customers' }" @click="setActiveSection('customers')">{{ text.nav_customers }}</button>
              </div>
            </div>

            <div class="sidebar-footer">
              <button type="button" class="nav-button" @click="refreshData">{{ text.btn_refresh }}</button>
              <button type="button" class="nav-button" @click="handleLogout">{{ text.btn_logout }}</button>
            </div>
          </aside>

          <main class="main">
            <header class="topbar glass">
              <div>
                <span class="brand-kicker">{{ currentSectionMeta.kicker }}</span>
                <h2>{{ text[currentSectionMeta.titleKey] }}</h2>
                <p>{{ text[currentSectionMeta.descKey] }}</p>
              </div>
              <div class="status-chip">{{ systemStatusText }}</div>
            </header>

            <section v-show="state.activeSection === 'dashboard'" class="panel-grid">
              <div class="stats-grid">
                <div v-for="card in summaryCards" :key="card.label" class="metric-card">
                  <div class="metric-label">{{ card.label }}</div>
                  <div class="metric-value">{{ card.value }}</div>
                </div>
              </div>

              <div class="dual-grid">
                <article class="glass card">
                  <div class="card-head">
                    <div>
                      <h3 class="card-title">{{ text.recent_activity }}</h3>
                      <p class="card-copy">{{ text.recent_activity_copy }}</p>
                    </div>
                  </div>
                  <div class="event-list">
                    <div v-if="!recentEvents.length" class="empty-state">{{ text.recent_activity_copy }}</div>
                    <div v-for="event in recentEvents" :key="event.timestamp + event.type" class="event-item">
                      <div class="event-head">
                        <span class="pill" :class="event.status === 'success' ? 'success' : 'failure'">{{ event.type || '-' }}</span>
                        <span class="event-meta">{{ event.timestamp || '-' }}</span>
                      </div>
                      <div><strong>{{ event.phone || 'System' }}</strong></div>
                      <div class="event-meta">{{ event.detail || '-' }}</div>
                    </div>
                  </div>
                </article>

                <article class="glass card">
                  <div class="card-head">
                    <div>
                      <h3 class="card-title">{{ text.provider_status }}</h3>
                      <p class="card-copy">{{ text.provider_status_copy }}</p>
                    </div>
                  </div>
                  <div class="provider-list">
                    <div v-if="!providers.length" class="empty-state">{{ text.provider_unknown }}</div>
                    <div v-for="provider in providers" :key="provider.provider" class="event-item">
                      <div class="event-head">
                        <strong>{{ String(provider.provider || '-').toUpperCase() }}</strong>
                        <span class="pill" :class="provider.health || 'warning'">{{ provider.health || 'unknown' }}</span>
                      </div>
                      <div class="event-meta">Latency: {{ provider.operations?.send?.latency_avg_ms ?? 0 }} ms</div>
                      <div class="event-meta">Failures in window: {{ provider.failures_in_window ?? 0 }}</div>
                    </div>
                  </div>
                </article>
              </div>
            </section>

            <section v-show="state.activeSection === 'verify-phone'" class="panel-grid">
              <article class="glass card">
                <div class="card-head">
                  <div>
                    <h3 class="card-title">{{ text.verify_phone_title }}</h3>
                    <p class="card-copy">{{ text.verify_phone_copy }}</p>
                  </div>
                </div>

                <div class="field-grid">
                  <div class="field">
                    <label>{{ text.label_customer_id }}</label>
                    <input v-model="state.verifyForm.id" type="text" placeholder="CUS-001">
                  </div>
                  <div class="field">
                    <label>{{ text.label_customer_name }}</label>
                    <input v-model="state.verifyForm.name" type="text" placeholder="Sokha Chan">
                  </div>
                  <div class="field">
                    <label>{{ text.label_phone }}</label>
                    <input v-model="state.verifyForm.phone_number" type="text" placeholder="0971234567">
                  </div>
                  <div class="field">
                    <label>{{ text.label_customer_otp }}</label>
                    <input v-model="state.verifyForm.otp" type="text" maxlength="6" inputmode="numeric" placeholder="123456">
                  </div>
                </div>

                <div class="button-row">
                  <button type="button" class="ghost-button" :disabled="state.verifyBusy" @click="saveVerifyCustomerRecord()">{{ text.btn_save_customer }}</button>
                  <button type="button" class="button" :disabled="state.verifyBusy" @click="requestStaffOtp">{{ text.btn_send_otp }}</button>
                  <button type="button" class="ghost-button" :disabled="state.verifyBusy" @click="resetVerifyForm">{{ text.btn_reset }}</button>
                </div>

                <div v-if="state.verifyStepReady">
                  <div class="note-panel">
                    <strong>{{ text.verify_step_ready }}</strong>
                    <div>{{ text.sent_to }}: <strong>{{ state.verifyForm.phone_number || '-' }}</strong></div>
                    <div>{{ text.expires_in }}: <strong>{{ verifyCountdownText }}</strong></div>
                  </div>
                  <div class="button-row">
                    <button type="button" class="button" :disabled="state.verifyBusy" @click="verifyStaffOtp">{{ text.btn_verify_otp }}</button>
                  </div>
                </div>

                <div v-if="getStatusMessage('verify')" class="status-panel" :class="state.status.verify.type">
                  {{ getStatusMessage('verify') }}
                </div>
              </article>
            </section>

            <section v-show="state.activeSection === 'customers'" class="panel-grid">
              <article class="glass card">
                <div class="card-head">
                  <div>
                    <h3 class="card-title">{{ text.customers_title }}</h3>
                    <p class="card-copy">{{ text.customers_copy }}</p>
                  </div>
                </div>

                <div class="toolbar">
                  <div class="button-row">
                    <button class="ghost-button" @click="downloadTemplate">{{ text.btn_download_template }}</button>
                    <button class="ghost-button" @click="triggerCustomerImport">{{ text.btn_import_excel }}</button>
                    <button class="ghost-button" @click="exportCustomers('xlsx')">{{ text.btn_export_excel }}</button>
                    <button class="ghost-button" @click="exportCustomers('csv')">{{ text.btn_export_csv }}</button>
                  </div>
                  <input v-model="state.searchQuery" class="search-input" type="text" :placeholder="text.search_placeholder">
                </div>

                <input ref="customerFileInput" class="hidden" type="file" accept=".xlsx,.xls,.csv" @change="importCustomerFile">

                <div v-if="getStatusMessage('customers')" class="status-panel" :class="state.status.customers.type">
                  {{ getStatusMessage('customers') }}
                </div>

                <div class="card-head" style="margin-top: 18px;">
                  <div>
                    <h3 class="card-title">{{ text.customer_table_title }}</h3>
                    <p class="card-copy">{{ text.customer_table_copy }}</p>
                  </div>
                </div>

                <div class="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>{{ text.label_customer_id }}</th>
                        <th>{{ text.label_customer_name }}</th>
                        <th>{{ text.label_customer_phone }}</th>
                        <th>{{ text.label_customer_otp }}</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-if="!filteredCustomers.length">
                        <td colspan="4" class="empty-state">{{ text.table_empty }}</td>
                      </tr>
                      <tr v-for="customer in filteredCustomers" :key="customer.id">
                        <td>{{ customer.id }}</td>
                        <td>{{ customer.name }}</td>
                        <td>{{ customer.phone_number }}</td>
                        <td>{{ customer.otp || '' }}</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </article>
            </section>

            <transition name="verify-fade">
              <div v-if="state.verifyPopup.open" class="popup-overlay" :class="state.verifyPopup.mode" role="status" aria-live="polite" aria-modal="true">
                <div class="popup-card glass">
                  <div v-if="state.verifyPopup.mode === 'loading'" class="popup-spinner" aria-hidden="true"></div>
                  <div v-else class="popup-check" aria-hidden="true">✓</div>
                  <div class="popup-title">
                    {{ state.verifyPopup.mode === 'loading' ? 'Loading' : 'Success' }}
                  </div>
                  <div class="popup-message">{{ state.verifyPopup.message }}</div>
                </div>
              </div>
            </transition>
          </main>
        </div>
      </div>
    </div>
  `
}).mount("#app");
