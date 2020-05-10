using System;
using System.IO;
using System.Collections.Generic;
using System.Data.Entity.Validation;
using System.Linq;
using System.Web;
using System.Web.Helpers;
using System.Web.Mvc;
using System.Web.Security;
using jaj.Models;
using System.Security.Principal;
using Microsoft.AspNet.Identity;

namespace jaj.Controllers
{
    public class UserController : Controller
    {
        DbBaza db = new DbBaza();

        //ActionResult za registraciju - HttpGet
        public ActionResult Registration()
        {
            return View();
        }

        //HttpPost ActionResult za registraciju
        [HttpPost]
        //[ValidateAntiForgeryToken]
        public ActionResult Registration(user user1)
        {
            string fileName = Path.GetFileNameWithoutExtension(user1.userInfo.FileName);
            string extension = Path.GetExtension(user1.userInfo.FileName);

            fileName = fileName + DateTime.Now.ToString("yymmssfff") + extension;
            user1.profilePicture = "~/PPDir/" + fileName;
            fileName = Path.Combine(Server.MapPath("~/PPDir/"), fileName);
            user1.userInfo.SaveAs(fileName);

            // Validacija modela
            if (ModelState.IsValid)
            {
                // Hashing lozinke - preuzima se lozinka koju korisnik unosi i hashira se - takva se pohranjuje u bazu podataka
                // Znači da ne spremamo čisti string u bazu podataka,što je doprinosi sigurnosti računa korisnika
                user1.Password = Crypto.Hash(user1.Password);
                user1.ConfirmPassword = Crypto.Hash(user1.ConfirmPassword);



                // Pohranjivanje podataka u bazu podataka
                using (DbBaza dc = new DbBaza())
                {

                    

                    dc.userInfo.Add(user1);
                    try
                    {  
                        dc.SaveChanges();
                    }
                    catch (DbEntityValidationException ex)
                    {
                        foreach (var entityValidationErrors in ex.EntityValidationErrors)
                        {
                            foreach (var validationError in entityValidationErrors.ValidationErrors)
                            {
                                Response.Write("Property: " + validationError.PropertyName + " Error: " + validationError.ErrorMessage);
                            }
                        }
                    }
                    RedirectToAction("Index");
                }
            }

            return View(user1);
        }


        // HttpGet Akcija za login
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }


        //HttpPost akcija za login,prosljeduje model login koji sadrži email i hashiranu lozinku usera
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(user login)
        {
            string message = "";

            using (DbBaza dc = new DbBaza())
            {
                // u varijablu v spremamo email koji smo unijeli prilikom logina
                var v = dc.userInfo.Where(a => a.Email == login.Email).FirstOrDefault();
                if (v != null)
                {
                    // Tu imamo znaci usporedbu lozinka,one upisane u login formi i lozinke koja je u bazi podataka od toga usera
                    // samo kaj se prvo ova unesena lozinka mora isto hashirati jer se inace nemre uspoređivati s ovom u bazi
                    // zbog toga ovaj Crypto.Hash
                    if (string.Compare(Crypto.Hash(login.Password), v.Password) == 0)
                    {
                        // Ovo je auth cookie - postavlja usera s tim emailom na status da je ulogirani
                        FormsAuthentication.SetAuthCookie(login.Email, false);
                        // Tu vadimo sve informacije o useru koji ima taj upisani email prilikom logina
                        var userDetails = dc.userInfo.Where(x => x.Email == login.Email).FirstOrDefault();
                        // Mi netrebamo bar za sad nist drugo osim userId,tak da se samo on vadi iz userDetailsa i sprema v varijablu
                        var userID = userDetails.UserID;
                        // E sad trebamo spremiti v nekom obliku taj userId da se ne zgubi prilikom premjestanja v drugi kontroler pa sam
                        // koristil tempData - neka vrsta privremene varijable
                        TempData["mydata"] = userID;

                        
                        
 
                        Response.Write("Login uspjesan");
                    }

                    else
                    {
                        Response.Write("Login neuspjesan");
                    }
                }

                else
                {
                    message = "Invalid credential provided";
                }
            }
            ViewBag.Message = message;
            return View();
        }

        // [Authorize] -  Ograničava taj ActionResult da je dostupan samo userima koji su loginani
        [Authorize]
        [HttpPost]
        public ActionResult Logout()
        {
            // Označava da se user logoutal pa nema više pristup akcijama s [Authorize]
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }


        public ActionResult Welcome()
        {
            
            
            return View();
            

        }

    }
}