import "../main.scss";
import { Suspense, lazy } from "react";
import type { ClassKey } from "keycloakify/login";
import type { KcContext } from "./KcContext";
import { useI18n } from "./i18n";
import DefaultPage from "keycloakify/login/DefaultPage";
import Template from "./Template";
const UserProfileFormFields = lazy(
  () => import("keycloakify/login/UserProfileFormFields"),
);

const doMakeUserConfirmPassword = true;
const Login = lazy(() => import("./pages/Login"));
const LoginUpdatePassword = lazy(() => import("./pages/LoginUpdatePassword"));
const LoginOtp = lazy(() => import("./pages/LoginOtp"));
const LoginConfigTotp = lazy(() => import("./pages/LoginConfigTotp"));
const LoginResetOtp = lazy(() => import("./pages/LoginResetOtp"));
const Register = lazy(() => import("./pages/Register"));
const LoginPageExpired = lazy(() => import("./pages/LoginPageExpired"));

export default function KcPage(props: { kcContext: KcContext }) {
  const { kcContext } = props;

  const { i18n } = useI18n({ kcContext });

  return (
    <Suspense>
      {(() => {
        switch (kcContext.pageId) {
          case "login.ftl":
            return (
              <Login
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
              />
            );
          case "login-update-password.ftl":
            return (
              <LoginUpdatePassword
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
              />
            );
          case "login-otp.ftl":
            return (
              <LoginOtp
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
              />
            );
          case "login-config-totp.ftl":
            return (
              <LoginConfigTotp
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
              />
            );
          case "login-reset-otp.ftl":
            return (
              <LoginResetOtp
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
              />
            );
          case "register.ftl":
            return (
              <Register
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
                UserProfileFormFields={UserProfileFormFields}
                doMakeUserConfirmPassword={doMakeUserConfirmPassword}
              />
            );
          case "login-page-expired.ftl":
            return (
              <LoginPageExpired
                {...{ kcContext, i18n, classes }}
                Template={Template}
                doUseDefaultCss={false}
              />
            );

          default:
            return (
              <DefaultPage
                kcContext={kcContext}
                i18n={i18n}
                classes={classes}
                Template={Template}
                doUseDefaultCss={false}
                UserProfileFormFields={UserProfileFormFields}
                doMakeUserConfirmPassword={doMakeUserConfirmPassword}
              />
            );
        }
      })()}
    </Suspense>
  );
}

const darkMode =
  window.matchMedia("(prefers-color-scheme: dark)").matches ||
  document.documentElement.getAttribute("data-bs-theme") === "dark";

const classes = {
  kcHtmlClass: "",
  kcBodyClass:
    "mw-100 mh-100 min-vh-100 d-flex align-items-center justify-content-center" +
    (darkMode ? " bg-dark-subtle" : " bg-light"),
  kcLoginClass: "py-4",

  kcHeaderClass: "border-bottom mb-4 pb-4",
  kcHeaderWrapperClass: "",
  kcFormCardClass: "",
  kcLocaleMainClass: "d-none",

  kcFormHeaderClass: "opacity-90 pb-3",
  //kcInputWrapperClass: "",
  kcInputClass: "form-control",
  kcInputErrorMessageClass: "text-danger",
  kcAlertClass: "alert alert-warning",
  kcFormPasswordVisibilityButtonClass: "d-none",
  kcFormGroupClass: "d-flex flex-column form-group mb-3",
  kcFormSettingClass: "justify-content-between",

  kcContentWrapperClass: "d-flex justify-content-between align-items-top",

  kcLabelWrapperClass: "",
  kcLabelClass: "form-check-label",
  kcCheckboxInputClass: "form-check-input",
  kcLoginOTPListInputClass: "form-check-input",
  kcLoginOTPListClass: "form-check-label",

  kcFormButtonsClass: "",
  kcFormOptionsClass: "mb-3",

  kcButtonClass: "btn w-100",
  //kcButtonLargeClass: "w-100",
  kcButtonPrimaryClass: "btn-primary",
  kcButtonDefaultClass: "btn-outline-primary",

  kcSignUpClass: "d-flex justify-content-center",

  kcFormSocialAccountSectionClass: "mt-3 text-center",
  kcFormSocialAccountListClass: "mt-3 list-inline d-flex flex-column gap-2",
  kcFormSocialAccountListButtonClass:
    "btn btn-outline-primary w-100 d-flex align-items-center justify-content-center position-relative",
} satisfies { [key in ClassKey]?: string };
