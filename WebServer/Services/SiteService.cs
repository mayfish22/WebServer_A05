using Microsoft.AspNetCore.Localization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WebServer.Models;
using WebServer.Models.WebServerDB;

namespace WebServer.Services
{
    public class SiteService
    {
        private readonly WebServerDBContext _WebServerDBContext;
        private readonly IHttpContextAccessor _context;
        private readonly IConfiguration _configuration;

        public SiteService(WebServerDBContext WebServerDBContext,
            IHttpContextAccessor context,
            IConfiguration configuration)
        {
            _WebServerDBContext = WebServerDBContext;
            _context = context;
            _configuration = configuration;
        }

        /// <summary>
        /// 字串加密
        /// </summary>
        /// <param name="input"></param>
        /// <returns>SHA512</returns>
        public string EncoderSHA512(string input)
        {
            string salt = _configuration.GetValue<string>("Salt");
            var message = Encoding.UTF8.GetBytes(salt + input);
            using (var alg = SHA512.Create())
            {
                string output = string.Empty;

                var hashValue = alg.ComputeHash(message);
                foreach (byte x in hashValue)
                {
                    output += String.Format("{0:x2}", x);
                }
                return output;
            }
        }

        /// <summary>
        /// 記錄使用者資訊到Session
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public async Task SetUserProfile(string id)
        {
            await Task.Yield();
            var user = _WebServerDBContext.User.Find(id);
            _context?.HttpContext?.Session.SetString("CurrentUser", JsonSerializer.Serialize(new UserProfileModel
            {
                ID = user?.ID,
                Account = user?.Account,
                DisplayName = user?.Name,
                Email = user?.Email,
            }));
        }

        /// <summary>
        /// 從Session讀取使用者資訊
        /// </summary>
        /// <returns>UserProfile</returns>
        public async Task<UserProfileModel?> GetUserProfile()
        {
            await Task.Yield();
            var UserSessionString = _context?.HttpContext?.Session.GetString("CurrentUser");
            if (string.IsNullOrEmpty(UserSessionString))
            {
                return null;
            }
            return JsonSerializer.Deserialize<UserProfileModel>(UserSessionString);
        }

        /// <summary>
        /// 取得語言設定
        /// </summary>
        /// <returns></returns>
        public string[] GetCultures()
        {
            return _WebServerDBContext.Language
                    .Where(s => s.IsEnabled == 1)
                    .OrderBy(s => s.Seq)
                    .Select(s => s.ID)
                    .ToArray();
        }

        /// <summary>
        /// 設定語言
        /// </summary>
        /// <param name="culture"></param>
        public void SetCulture(string? culture = null)
        {
            if (string.IsNullOrEmpty(culture))
            {
                if (_context.HttpContext!.Request.Cookies.ContainsKey(CookieRequestCultureProvider.DefaultCookieName))
                {
                    var name = _context.HttpContext.Request.Cookies[CookieRequestCultureProvider.DefaultCookieName]!;
                    culture = CookieRequestCultureProvider.ParseCookieValue(name)?.Cultures.FirstOrDefault().Value;
                }
                else
                {
                    culture = GetCultures()[0];
                }
            }
            //將設定寫入Cookie
            _context.HttpContext!.Response.Cookies.Append(
                CookieRequestCultureProvider.DefaultCookieName,
                CookieRequestCultureProvider.MakeCookieValue(new RequestCulture(culture!)),
                new CookieOptions { Expires = DateTimeOffset.UtcNow.AddYears(1) }
            );
        }

        /// <summary>
        /// 當前的語言設定
        /// </summary>
        /// <returns></returns>
        public string GetCurrentCulture()
        {
            var cultures = GetCultures();
            var currentCulture = cultures[0];
            if (_context.HttpContext!.Request.Cookies.ContainsKey(CookieRequestCultureProvider.DefaultCookieName))
            {
                //若有記錄
                var name = _context.HttpContext.Request.Cookies[CookieRequestCultureProvider.DefaultCookieName]!;            
                currentCulture = CookieRequestCultureProvider.ParseCookieValue(name)?.Cultures.FirstOrDefault().Value;
            }
            if (Array.IndexOf(cultures, currentCulture) < 0)
            {
                //沒有記錄
                currentCulture = cultures[0];
            }
            return currentCulture!;
        }
    }
}