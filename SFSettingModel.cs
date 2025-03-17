namespace FinalSFIntegration.Models
{
    public class SalesforceSettings
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUri { get; set; }
        public string AuthorizeUrl { get; set; }
        public string TokenUrl { get; set; }
    }
}
