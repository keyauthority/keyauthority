package net.keyauthority.agent;

import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;

import java.lang.instrument.Instrumentation;

import static net.bytebuddy.matcher.ElementMatchers.named;

public class MultiAudienceAgent {
    public static void premain(String args, Instrumentation inst) {
        System.out.println("[multi-audience-agent] premain loaded");
        new AgentBuilder.Default()
            .type(named("org.keycloak.authentication.authenticators.client.AbstractBaseJWTValidator"))
            .transform((builder, td, cl, module, pd) ->
                builder.visit(Advice.to(ForceMultiAudienceAllowed.class).on(named("validateTokenAudience")))
            )
            .installOn(inst);
    }

    public static class ForceMultiAudienceAllowed {
        @Advice.OnMethodEnter
        static void onEnter(@Advice.Argument(value = 1, readOnly = false) boolean multipleAudienceAllowed) {
            multipleAudienceAllowed = true;
            // System.out.println("[multi-audience-agent] forced multipleAudienceAllowed=true");
        }
    }
}