using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=baza.db"));

var secretKey = "SuperTajneHasloNaZaliczenieWymaga32Znakow!!!";
var key = Encoding.ASCII.GetBytes(secretKey);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(x =>
    {
        x.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

// TEN FRAGMENT SAM TWORZY BAZÊ DANYCH (ZAMIAST KOMEND W KONSOLI)
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (UserDto data, AppDbContext db) =>
{
    var exists = await db.Users.AnyAsync(x => x.Email == data.Email);
    if (exists) return Results.BadRequest();

    var u = new User();
    u.Email = data.Email;
    u.Password = BCrypt.Net.BCrypt.HashPassword(data.Password);

    db.Users.Add(u);
    await db.SaveChangesAsync();
    return Results.Ok();
});

app.MapPost("/login", async (UserDto data, AppDbContext db) =>
{
    var u = await db.Users.FirstOrDefaultAsync(x => x.Email == data.Email);
    if (u == null) return Results.Unauthorized();

    var ok = BCrypt.Net.BCrypt.Verify(data.Password, u.Password);
    if (!ok) return Results.Unauthorized();

    var tokenHandler = new JwtSecurityTokenHandler();
    var desc = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, u.Id.ToString()) }),
        Expires = DateTime.UtcNow.AddDays(2),
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };
    var token = tokenHandler.CreateToken(desc);

    return Results.Ok(tokenHandler.WriteToken(token));
});

app.MapGet("/notes", async (AppDbContext db, ClaimsPrincipal user) =>
{
    var idString = user.FindFirst(ClaimTypes.NameIdentifier)!.Value;
    var userId = int.Parse(idString);

    var list = await db.Notes
        .Where(x => x.UserId == userId)
        .Select(x => new { x.Id, x.Content })
        .ToListAsync();

    return Results.Ok(list);
}).RequireAuthorization();

app.MapPost("/notes", async (NoteDto data, AppDbContext db, ClaimsPrincipal user) =>
{
    var idString = user.FindFirst(ClaimTypes.NameIdentifier)!.Value;
    var userId = int.Parse(idString);

    var n = new Note();
    n.Content = data.Content;
    n.UserId = userId;

    db.Notes.Add(n);
    await db.SaveChangesAsync();

    return Results.Created($"/notes/{n.Id}", new { n.Id, n.Content });
}).RequireAuthorization();

app.MapPut("/notes/{id}", async (int id, NoteDto data, AppDbContext db, ClaimsPrincipal user) =>
{
    var idString = user.FindFirst(ClaimTypes.NameIdentifier)!.Value;
    var userId = int.Parse(idString);

    var n = await db.Notes.FindAsync(id);
    if (n == null) return Results.NotFound();
    if (n.UserId != userId) return Results.Forbid();

    n.Content = data.Content;
    await db.SaveChangesAsync();

    return Results.NoContent();
}).RequireAuthorization();

app.MapDelete("/notes/{id}", async (int id, AppDbContext db, ClaimsPrincipal user) =>
{
    var idString = user.FindFirst(ClaimTypes.NameIdentifier)!.Value;
    var userId = int.Parse(idString);

    var n = await db.Notes.FindAsync(id);
    if (n == null) return Results.NotFound();
    if (n.UserId != userId) return Results.Forbid();

    db.Notes.Remove(n);
    await db.SaveChangesAsync();

    return Results.NoContent();
}).RequireAuthorization();

app.Run();

class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
    public DbSet<User> Users { get; set; }
    public DbSet<Note> Notes { get; set; }
}

class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}

class Note
{
    public int Id { get; set; }
    public string Content { get; set; }
    public int UserId { get; set; }
}

class UserDto
{
    public string Email { get; set; }
    public string Password { get; set; }
}

class NoteDto
{
    public int? Id { get; set; }
    public string Content { get; set; }
}