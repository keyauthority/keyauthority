import { getKcClsx, KcClsx } from "keycloakify/login/lib/kcClsx";
import { kcSanitize } from "keycloakify/lib/kcSanitize";
import type { PageProps } from "keycloakify/login/pages/PageProps";
import type { KcContext } from "../KcContext";
import type { I18n } from "../i18n";

export default function LoginConfigTotp(
  props: PageProps<
    Extract<KcContext, { pageId: "login-config-totp.ftl" }>,
    I18n
  >,
) {
  const { kcContext, i18n, doUseDefaultCss, Template, classes } = props;

  const { kcClsx } = getKcClsx({
    doUseDefaultCss,
    classes,
  });

  const { url, isAppInitiatedAction, totp, mode, messagesPerField } = kcContext;

  const { msg, msgStr, advancedMsg } = i18n;

  let idx = 1;

  return (
    <Template
      kcContext={kcContext}
      i18n={i18n}
      doUseDefaultCss={doUseDefaultCss}
      classes={classes}
      headerNode={msg("loginTotpTitle")}
      displayMessage={!messagesPerField.existsError("totp", "userLabel")}
    >
      <>
        <div id="kc-totp-settings" className="mb-3">
          <div className="mb-3">
            {idx++}. {msg("loginTotpStep1")}
            <ul id="kc-totp-supported-apps" className="mt-1">
              {totp.supportedApplications.map((app) => (
                <li key={app}>{advancedMsg(app)}</li>
              ))}
            </ul>
          </div>

          {mode == "manual" ? (
            <>
              <div className="mb-3">
                {idx++}. {msg("loginTotpManualStep2")}
                <p className="my-1">
                  <div
                    className="text-center border bg-light-subtle rounded p-1"
                    id="kc-totp-secret-key"
                  >
                    {totp.totpSecretEncoded}
                  </div>
                </p>
                <p>
                  <a href={totp.qrUrl} id="mode-barcode">
                    {msg("loginTotpScanBarcode")}
                  </a>
                </p>
              </div>
              <div className="mb-3">
                {idx++}. {msg("loginTotpManualStep3")}
                <ul className="mt-1">
                  <li id="kc-totp-type">
                    {msg("loginTotpType")}:{" "}
                    {msg(`loginTotp.${totp.policy.type}`)}
                  </li>
                  <li id="kc-totp-algorithm">
                    {msg("loginTotpAlgorithm")}: {totp.policy.getAlgorithmKey()}
                  </li>
                  <li id="kc-totp-digits">
                    {msg("loginTotpDigits")}: {totp.policy.digits}
                  </li>
                  {totp.policy.type === "totp" ? (
                    <li id="kc-totp-period">
                      {msg("loginTotpInterval")}: {totp.policy.period}
                    </li>
                  ) : (
                    <li id="kc-totp-counter">
                      {msg("loginTotpCounter")}: {totp.policy.initialCounter}
                    </li>
                  )}
                </ul>
              </div>
            </>
          ) : (
            <div className="mb-3">
              {idx++}. {msg("loginTotpStep2")}
              <div className="mx-auto py-2" style={{ width: "fit-content" }}>
                <img
                  style={{ width: "200px", height: "200px" }}
                  id="kc-totp-secret-qr-code"
                  src={`data:image/png;base64, ${totp.totpSecretQrCode}`}
                  alt="Figure: Barcode"
                />
              </div>
              <div>
                <a href={totp.manualUrl} id="mode-manual">
                  {msg("loginTotpUnableToScan")}
                </a>
              </div>
            </div>
          )}
          <div className="mb-3">
            <p>
              {idx++}. {msg("loginTotpStep3")}
            </p>
            <p>{msg("loginTotpStep3DeviceName")}</p>
          </div>
        </div>

        <form
          action={url.loginAction}
          className={kcClsx("kcFormClass")}
          id="kc-totp-settings-form"
          method="post"
        >
          <div className={kcClsx("kcFormGroupClass")}>
            <div className={kcClsx("kcInputWrapperClass")}>
              <label htmlFor="totp" className={kcClsx("kcLabelClass")}>
                {msg("authenticatorCode")}
              </label>{" "}
              <span className="required">*</span>
            </div>
            <div className={kcClsx("kcInputWrapperClass")}>
              <input
                type="text"
                id="totp"
                name="totp"
                autoComplete="off"
                className={kcClsx("kcInputClass")}
                aria-invalid={messagesPerField.existsError("totp")}
              />

              {messagesPerField.existsError("totp") && (
                <span
                  id="input-error-otp-code"
                  className={kcClsx("kcInputErrorMessageClass")}
                  aria-live="polite"
                  dangerouslySetInnerHTML={{
                    __html: kcSanitize(messagesPerField.get("totp")),
                  }}
                />
              )}
            </div>
            <input
              type="hidden"
              id="totpSecret"
              name="totpSecret"
              value={totp.totpSecret}
            />
            {mode && <input type="hidden" id="mode" value={mode} />}
          </div>

          <div className={kcClsx("kcFormGroupClass")}>
            <div className={kcClsx("kcInputWrapperClass")}>
              <label htmlFor="userLabel" className={kcClsx("kcLabelClass")}>
                {msg("loginTotpDeviceName")}
              </label>{" "}
              {totp.otpCredentials.length >= 1 && (
                <span className="required">*</span>
              )}
            </div>
            <div className={kcClsx("kcInputWrapperClass")}>
              <input
                type="text"
                id="userLabel"
                name="userLabel"
                autoComplete="off"
                className={kcClsx("kcInputClass")}
                aria-invalid={messagesPerField.existsError("userLabel")}
              />
              {messagesPerField.existsError("userLabel") && (
                <span
                  id="input-error-otp-label"
                  className={kcClsx("kcInputErrorMessageClass")}
                  aria-live="polite"
                  dangerouslySetInnerHTML={{
                    __html: kcSanitize(messagesPerField.get("userLabel")),
                  }}
                />
              )}
            </div>
          </div>

          <div className={kcClsx("kcFormGroupClass").replace(/mb-3/g, "mb-1")}>
            <LogoutOtherSessions kcClsx={kcClsx} i18n={i18n} />
          </div>

          {isAppInitiatedAction ? (
            <>
              <input
                type="submit"
                className={kcClsx(
                  "kcButtonClass",
                  "kcButtonPrimaryClass",
                  "kcButtonLargeClass",
                )}
                id="saveTOTPBtn"
                value={msgStr("doSubmit")}
              />
              <button
                type="submit"
                className={kcClsx(
                  "kcButtonClass",
                  "kcButtonDefaultClass",
                  "kcButtonLargeClass",
                  "kcButtonLargeClass",
                )}
                id="cancelTOTPBtn"
                name="cancel-aia"
                value="true"
              >
                {msg("doCancel")}
              </button>
            </>
          ) : (
            <input
              type="submit"
              className={kcClsx(
                "kcButtonClass",
                "kcButtonPrimaryClass",
                "kcButtonLargeClass",
              )}
              id="saveTOTPBtn"
              value={msgStr("doSubmit")}
            />
          )}
        </form>
      </>
    </Template>
  );
}

function LogoutOtherSessions(props: { kcClsx: KcClsx; i18n: I18n }) {
  const { kcClsx, i18n } = props;

  const { msg } = i18n;

  return (
    <div id="kc-form-options" className={kcClsx("kcFormOptionsClass")}>
      <div className={kcClsx("kcFormOptionsWrapperClass")}>
        <div className={kcClsx("kcLabelWrapperClass") + " form-check"}>
          <input
            className={kcClsx("kcCheckboxInputClass")}
            type="checkbox"
            id="logout-sessions"
            name="logout-sessions"
            value="on"
            defaultChecked={true}
          />
          <label className={kcClsx("kcLabelClass")}>
            {msg("logoutOtherSessions")}
          </label>
        </div>
      </div>
    </div>
  );
}
