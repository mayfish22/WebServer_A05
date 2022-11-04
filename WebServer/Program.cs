using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using WebServer.Extensions;
using WebServer.Models.WebServerDB;
using WebServer.Services;

namespace WebServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            //多國語系
            //將當地語系化服務新增至服務容器。
            builder.Services.AddLocalization();
            builder.Services.AddControllersWithViews()
                //在 cshtml 中使用多國語言
                .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
                //在 Model 中使用多國語言
                .AddDataAnnotationsLocalization(
                options =>
                {
                    options.DataAnnotationLocalizerProvider = (type, factory) =>
                    factory.Create(typeof(Resource));
                });

            //設定連線字串
            builder.Services.AddDbContext<WebServerDBContext>(options =>
            {
                options.UseSqlite(builder.Configuration.GetConnectionString("WebServerDB"));
            });

            // 使用 Session
            builder.Services.AddDistributedMemoryCache();

            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(60);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
            });

            // 使用 Cookie
            builder.Services
                .AddAuthentication(Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    //存取被拒轉跳頁面
                    options.AccessDeniedPath = new PathString("/Account/Signin");
                    //登入頁
                    options.LoginPath = new PathString("/Account/Signin");
                    //登出頁
                    options.LogoutPath = new PathString("/Account/Signout");
                });

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddScoped<SiteService>();
            builder.Services.AddScoped<ValidatorService>();
            builder.Services.AddScoped<EmailService>();
            builder.Services.AddScoped<IViewRenderService, ViewRenderService>();

            var app = builder.Build();

            ServiceActivator.Configure(app.Services);

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            using (var serviceScope = ServiceActivator.GetScope())
            {
                //從DI Container 取得 Service
                var siteService = (SiteService?)serviceScope?.ServiceProvider.GetService(typeof(SiteService));
                //從資料庫中取得語系
                var cultures = siteService?.GetCultures();

                var localizationOptions = new RequestLocalizationOptions()
                    .SetDefaultCulture(cultures![0])//預設值
                    .AddSupportedCultures(cultures)
                    .AddSupportedUICultures(cultures);
                localizationOptions.RequestCultureProviders = new List<IRequestCultureProvider>{
                    //由 url 查詢字串來設定 CultureInfo 
                    new QueryStringRequestCultureProvider(),
                    //由 Cookie 追蹤使用者慣用文化特性資訊
                    new CookieRequestCultureProvider(),
                    //過瀏覽器要求的 Accept-Language HTTP 標頭來偵測使用者的慣用語言
                    new AcceptLanguageHeaderRequestCultureProvider(),
                };
                app.UseRequestLocalization(localizationOptions);
            }

            app.UseRouting();

            app.UseAuthentication();//驗證

            app.UseAuthorization();//授權 

            app.UseSession();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}