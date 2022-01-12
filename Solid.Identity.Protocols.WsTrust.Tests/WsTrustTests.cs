using Microsoft.IdentityModel.Protocols.WsAddressing;
using Microsoft.IdentityModel.Protocols.WsPolicy;
using Microsoft.IdentityModel.Protocols.WsTrust;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using Solid.Identity.Protocols.WsTrust.Tests.Host.Tokens;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Security;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Xunit;
using Xunit.Abstractions;

namespace Solid.Identity.Protocols.WsTrust.Tests
{
    public class WsTrustTests : IClassFixture<WsTrustTestsFixture>
    {
        private WsTrustTestsFixture _fixture;

        public WsTrustTests(WsTrustTestsFixture fixture, ITestOutputHelper output)
        {
            fixture.SetOutput(output);
            _fixture = fixture;
        }

        [Fact]
        public async Task ShouldValidateIssuerAsAudience()
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
            };
            var client = _fixture.CreateWsTrust13IssuedTokenClient("userName", appliesTo: WsTrustTestsFixture.Issuer);
            var token = await client.IssueAsync(request);

            Assert.NotNull(token);
        }

        [Fact]
        public async Task ShouldValidateRequestUrlAsAudience()
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
            };
            var client = _fixture.CreateWsTrust13IssuedTokenClient("userName", appliesTo: $"{_fixture.TestingServer.BaseAddress}trust/13");
            var response = await client.IssueAsync(request);

            var token = response.GetRequestedSecurityToken();
            Assert.NotNull(token);
        }

        [Theory]
        [InlineData(WsTrustTestsFixture.SamlTokenType)]
        [InlineData(WsTrustTestsFixture.Saml2TokenType)]
        [InlineData("urn:god")]
        [InlineData("urn:deity")]
        public async Task ShouldValidateToken(string clientTokenType)
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
            };
            var client = _fixture.CreateWsTrust13IssuedTokenClient("userName", clientTokenType: clientTokenType);
            var response = await client.IssueAsync(request);

            var token = response.GetRequestedSecurityToken();
            Assert.NotNull(token);
        }

        [Theory]
        [InlineData(WsTrustTestsFixture.SamlTokenType)]
        [InlineData(WsTrustTestsFixture.Saml2TokenType)]
        public async Task ShouldValidateTokenWithEmbeddedCertificate(string clientTokenType)
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
            };
            var client = _fixture.CreateWsTrust13IssuedTokenClient("userName", issuer: "urn:test:issuer:embedded_cert", clientTokenType: clientTokenType);
            var response = await client.IssueAsync(request);

            var token = response.GetRequestedSecurityToken();
            Assert.NotNull(token);
        }

        [Theory]
        [InlineData(Certificates.ValidBase64)]
        public async Task ShouldNotValidateAlteredSignedToken(string base64)
        {
            using (var certificate = new X509Certificate2(Convert.FromBase64String(base64)))
            {
                var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
                {
                    KeyType = WsTrustKeyTypes.Trust13.Bearer,
                    AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
                };
                var settings = new XmlWriterSettings { Indent = true };
                var client = _fixture.CreateWsTrust13CertificateClient(certificate, settings);
                var exception = null as Exception;
                try
                {
                    _ = await client.IssueAsync(request);
                }
                catch (Exception ex)
                {
                    exception = ex;
                }

                Assert.NotNull(exception);
                Assert.IsType<MessageSecurityException>(exception);
            }
        }

        [Theory]
        [MemberData(nameof(ShouldGetTokenWithUserNameData))]
        public async Task ShouldGetTokenWithUserName(GetTokenWithUserNameData data)
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
            };
            var client = _fixture.CreateWsTrust13UserNameClient(data.UserName, data.Password);

            var exception = null as Exception;
            var token = null as SecurityToken;
            try
            {
                var response = await client.IssueAsync(request);
                token = response.GetRequestedSecurityToken();
            }
            catch (Exception ex)
            {
                exception = ex;
            }

            if (data.ShouldFail)
            {
                Assert.NotNull(exception);
                Assert.IsType<MessageSecurityException>(exception);
            }
            else
            {
                Assert.NotNull(token);
            }
        }

        [Theory]
        [MemberData(nameof(ShouldGetTokenWithCertificateData))]
        public async Task ShouldGetTokenWithCertificate(GetTokenWithCertificateData data)
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests"))
            };
            using (var certificate = new X509Certificate2(Convert.FromBase64String(data.CertificateBase64)))
            {
                var client = _fixture.CreateWsTrust13CertificateClient(certificate);

                var exception = null as Exception;
                var token = null as SecurityToken;
                try
                {
                    var response = await client.IssueAsync(request);
                    token = response.GetRequestedSecurityToken();
                }
                catch (Exception ex)
                {
                    exception = ex;
                }

                if (data.ShouldFail)
                {
                    Assert.NotNull(exception);
                    Assert.IsType<MessageSecurityException>(exception);
                }
                else
                {
                    Assert.Null(exception);
                    Assert.NotNull(token); 
                }
            }
        }

        [Theory]
        [MemberData(nameof(ShouldGetTokenData))]
        public async Task ShouldGetToken(GetTokenData data)
        {
            var request = new WsTrustRequest(WsTrustActions.Trust13.Issue)
            {
                KeyType = WsTrustKeyTypes.Trust13.Bearer,
                AppliesTo = new AppliesTo(new EndpointReference("urn:tests")),
                TokenType = data.TokenTypeIdentifier
            };
            var client = _fixture.CreateWsTrust13IssuedTokenClient("userName");
            var response = await client.IssueAsync(request);

            var token = response.GetRequestedSecurityToken();

            Assert.NotNull(token);
            data.AssertToken(_fixture, token);
        }

        public static readonly TheoryData<GetTokenWithUserNameData> ShouldGetTokenWithUserNameData = new TheoryData<GetTokenWithUserNameData>
        {
            new GetTokenWithUserNameData
            {
                UserName = "userName",
                Password = "password"
            },
            new GetTokenWithUserNameData
            {
                UserName = "userName",
                Password = "incorrect",
                ShouldFail = true
            },
            new GetTokenWithUserNameData
            {
                UserName = "non-user",
                Password = "incorrect",
                ShouldFail = true
            }
        };

        public static readonly TheoryData<GetTokenWithCertificateData> ShouldGetTokenWithCertificateData = new TheoryData<GetTokenWithCertificateData>
        {
            new GetTokenWithCertificateData
            {
                Subject = "test.valid",
                CertificateBase64 = Certificates.ValidBase64,
                //SecurityAlgorithmSuite = SecurityAlgorithmSuite.Basic128
            },
            new GetTokenWithCertificateData
            {
                Subject = "test.valid",
                CertificateBase64 = Certificates.ValidBase64,
                //SecurityAlgorithmSuite = SecurityAlgorithmSuite.Basic256Sha256
            },
            new GetTokenWithCertificateData
            {
                Subject = "test.expired",
                CertificateBase64 = Certificates.ExpiredBase64,
                ShouldFail = true,
                //SecurityAlgorithmSuite = SecurityAlgorithmSuite.Basic128
            },
            new GetTokenWithCertificateData
            {
                Subject = "test.expired",
                CertificateBase64 = Certificates.ExpiredBase64,
                ShouldFail = true,
                //SecurityAlgorithmSuite = SecurityAlgorithmSuite.Basic256Sha256
            },
            new GetTokenWithCertificateData
            {
                Subject = "test.invalid",
                CertificateBase64 = Certificates.InvalidBase64,
                ShouldFail = true,
                //SecurityAlgorithmSuite = SecurityAlgorithmSuite.Basic128
            },
            new GetTokenWithCertificateData
            {
                Subject = "test.invalid",
                CertificateBase64 = Certificates.InvalidBase64,
                ShouldFail = true,
                //SecurityAlgorithmSuite = SecurityAlgorithmSuite.Basic256Sha256
            }
        };

        public static readonly TheoryData<GetTokenData> ShouldGetTokenData = new TheoryData<GetTokenData>
        {
            new GetTokenData
            {
                TokenTypeIdentifier = WsTrustTestsFixture.SamlTokenType,
                TokenType = typeof(SamlSecurityToken)
            },
            new GetTokenData
            {
                TokenTypeIdentifier = WsTrustTestsFixture.Saml2TokenType,
                TokenType = typeof(Saml2SecurityToken)
            },
            new GetTokenData
            {
                TokenTypeIdentifier = "urn:god",
                TokenType = typeof(GodSecurityToken)
            },
            new GetTokenData
            {
                TokenTypeIdentifier = "urn:deity",
                TokenType = typeof(GodSecurityToken)
            }
        };

        public class GetTokenWithCertificateData : IXunitSerializable
        {
            public string CertificateBase64 { get; set; }
            public bool ShouldFail { get; set; }
            public string Subject { get; set; }
            //public SecurityAlgorithmSuite SecurityAlgorithmSuite { get; set; }

            void IXunitSerializable.Serialize(IXunitSerializationInfo info)
            {
                info.AddValue(nameof(Subject), Subject);
                info.AddValue(nameof(ShouldFail), ShouldFail);
                info.AddValue(nameof(CertificateBase64), CertificateBase64);
                //info.AddValue(nameof(SecurityAlgorithmSuite), SecurityAlgorithmSuite?.ToString());
            }

            void IXunitSerializable.Deserialize(IXunitSerializationInfo info)
            {
                Subject = info.GetValue<string>(nameof(Subject));
                ShouldFail = info.GetValue<bool>(nameof(ShouldFail));
                CertificateBase64 = info.GetValue<string>(nameof(CertificateBase64));
                //var securityAlgorithmSuite = info.GetValue<string>(nameof(SecurityAlgorithmSuite));
                //if (securityAlgorithmSuite != null)
                //    SecurityAlgorithmSuite = typeof(SecurityAlgorithmSuite).GetProperty(securityAlgorithmSuite, BindingFlags.Static | BindingFlags.Public).GetValue(null) as SecurityAlgorithmSuite;
            }
        }

        public class GetTokenWithUserNameData : IXunitSerializable
        {
            public string UserName { get; set; }
            public string Password { get; set; }
            public bool ShouldFail { get; set; }

            void IXunitSerializable.Serialize(IXunitSerializationInfo info)
            {
                info.AddValue(nameof(UserName), UserName);
                info.AddValue(nameof(Password), Password);
                info.AddValue(nameof(ShouldFail), ShouldFail);
            }

            void IXunitSerializable.Deserialize(IXunitSerializationInfo info)
            {
                UserName = info.GetValue<string>(nameof(UserName));
                Password = info.GetValue<string>(nameof(Password));
                ShouldFail = info.GetValue<bool>(nameof(ShouldFail));
            }
        }

        public class GetTokenData : IXunitSerializable
        {
            public string TokenTypeIdentifier { get; set; }
            public Type TokenType { get; set; }

            public void AssertToken(WsTrustTestsFixture fixture, SecurityToken token)
            {
                var converted = fixture.ConvertSecurityToken(token, TokenType);
                Assert.NotNull(converted);
            }

            void IXunitSerializable.Deserialize(IXunitSerializationInfo info)
            {
                TokenTypeIdentifier = info.GetValue<string>(nameof(TokenTypeIdentifier));
                var tokenType = info.GetValue<string>(nameof(TokenType));
                TokenType = Type.GetType(tokenType);
            }

            void IXunitSerializable.Serialize(IXunitSerializationInfo info)
            {
                info.AddValue(nameof(TokenTypeIdentifier), TokenTypeIdentifier);
                info.AddValue(nameof(TokenType), TokenType.AssemblyQualifiedName);
            }
        }
    }
}
