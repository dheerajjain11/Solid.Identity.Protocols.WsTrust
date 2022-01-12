﻿using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.Identity.Protocols.WsSecurity.Tokens;
using Solid.Identity.Protocols.WsTrust;
using Solid.IdentityModel.Tokens.Saml2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class WsTrustOptionsExtensions_SecurityTokenHandlers
    {
        public static WsTrustOptions AddSamlSecurityTokenHandler(this WsTrustOptions options)
            => options.AddSecurityTokenHandler(provider => provider.GetService<SamlSecurityTokenHandler>() ?? new SamlSecurityTokenHandler(), SamlConstants.Namespace, SamlConstants.OasisWssSamlTokenProfile11);

        public static WsTrustOptions AddSaml2SecurityTokenHandler(this WsTrustOptions options)
            => options.AddSecurityTokenHandler(provider => provider.GetService<Saml2SecurityTokenHandler>() ?? new WsSecuritySaml2SecurityTokenHandler(), Saml2Constants.Saml2TokenProfile11, Saml2Constants.OasisWssSaml2TokenProfile11);
    }
}
