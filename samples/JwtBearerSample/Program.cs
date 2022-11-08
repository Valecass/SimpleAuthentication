using JwtBearerSample.Authentication;
using Microsoft.AspNetCore.Authentication;
using SimpleAuthentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllers();

builder.Services.AddSimpleAuthentication(builder.Configuration, setupAction: options =>
{
    options.CreateAndGetRefreshTokenMethod = async (username) =>
    {
        await Task.Delay(100);
        //create refresh token
        //store refresh token

        //in this sample we return the username as the refresh token
        return username;
    };

    options.VerifyRefreshTokenMethod = async (refreshToken, userName) =>
    {
        //verify refresk token
        await Task.Delay(100);
        //in this sample refresh token has to be the username
        return refreshToken == userName;
    };
});

//builder.Services.AddAuthorization(options =>
//{
//    options.FallbackPolicy = options.DefaultPolicy = new AuthorizationPolicyBuilder()
//                                .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
//                                .RequireAuthenticatedUser()
//                                .Build();

//    options.AddPolicy("Bearer", policy => policy
//                                .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
//                                .RequireAuthenticatedUser());
//});

// Uncomment the following line if you have multiple authentication schemes and
// you need to determine the authentication scheme at runtime (for example, you don't want to use the default authentication scheme).
//builder.Services.AddSingleton<IAuthenticationSchemeProvider, ApplicationAuthenticationSchemeProvider>();

builder.Services.AddTransient<IClaimsTransformation, ClaimsTransformer>();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(options =>
{
    options.AddSimpleAuthentication(builder.Configuration);
    
});

var app = builder.Build();
app.UseHttpsRedirection();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthenticationAndAuthorization();

app.MapControllers();

app.Run();