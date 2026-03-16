"""
Bugcrowd Report Scraper

Scrapes publicly disclosed vulnerability reports from Bugcrowd.
"""

import re
from typing import Optional
from pathlib import Path

from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import Progress, TaskID

from llm.scraper.base_scraper import BaseScraper, RawReport

console = Console()


class BugcrowdScraper(BaseScraper):
    """Scraper for Bugcrowd disclosed vulnerability reports."""
    
    SOURCE_NAME = "bugcrowd"
    BASE_URL = "https://bugcrowd.com"
    DISCLOSURES_URL = "https://bugcrowd.com/disclosures"
    REQUEST_DELAY = 1.5
    
    SEVERITY_MAP = {
        "p1": "critical",
        "p2": "high", 
        "p3": "medium",
        "p4": "low",
        "p5": "informational",
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    
    def _fetch_disclosures_page(self, page: int = 1) -> Optional[BeautifulSoup]:
        """Fetch a page of Bugcrowd disclosures."""
        url = f"{self.DISCLOSURES_URL}?page={page}"
        response = self._fetch_with_retry(url)
        
        if not response or response.status_code != 200:
            return None
        
        return BeautifulSoup(response.text, "html.parser")
    
    def _parse_disclosure_card(self, card) -> Optional[dict]:
        """Parse a disclosure card from the listings page."""
        try:
            # Extract disclosure link
            link = card.find("a", href=re.compile(r"/disclosures/"))
            if not link:
                return None
            
            href = link.get("href", "")
            disclosure_id = href.split("/")[-1].split("?")[0]
            
            # Extract title
            title_elem = card.find("h4") or card.find("h3") or link
            title = title_elem.get_text(strip=True) if title_elem else "Unknown"
            
            # Try to extract severity
            severity = "informational"
            severity_elem = card.find(class_=re.compile(r"priority|severity", re.I))
            if severity_elem:
                sev_text = severity_elem.get_text(strip=True).lower()
                for key, val in self.SEVERITY_MAP.items():
                    if key in sev_text:
                        severity = val
                        break
            
            # Extract program name
            program_elem = card.find(class_=re.compile(r"program|company", re.I))
            program = program_elem.get_text(strip=True) if program_elem else None
            
            return {
                "id": disclosure_id,
                "title": title,
                "url": f"{self.BASE_URL}{href}" if href.startswith("/") else href,
                "severity": severity,
                "program": program,
            }
            
        except Exception as e:
            console.print(f"[dim]Error parsing card: {e}[/dim]")
            return None
    
    def _fetch_disclosure_details(self, url: str) -> Optional[dict]:
        """Fetch full disclosure details from the disclosure page."""
        response = self._fetch_with_retry(url)
        if not response or response.status_code != 200:
            return None
        
        soup = BeautifulSoup(response.text, "html.parser")
        details = {}
        
        try:
            # Extract description/body
            body_selectors = [
                "div.disclosure-body",
                "div.disclosure-content",
                "article",
                "div.markdown-body",
                "main",
            ]
            
            for selector in body_selectors:
                body = soup.select_one(selector)
                if body:
                    details["body"] = body.get_text(separator="\n", strip=True)
                    break
            
            # Extract vulnerability type
            vuln_type_elem = soup.find(text=re.compile(r"vulnerability type|weakness", re.I))
            if vuln_type_elem:
                parent = vuln_type_elem.find_parent()
                if parent:
                    sibling = parent.find_next_sibling()
                    if sibling:
                        details["vuln_type"] = sibling.get_text(strip=True)
            
            # Extract CWE if present
            cwe_match = re.search(r"CWE-(\d+)", response.text)
            if cwe_match:
                details["cwe"] = f"CWE-{cwe_match.group(1)}"
            
            # Extract CVSS if present
            cvss_match = re.search(r"CVSS[:\s]*(\d+\.?\d*)", response.text, re.I)
            if cvss_match:
                details["cvss_score"] = float(cvss_match.group(1))
            
        except Exception as e:
            console.print(f"[dim]Error fetching details: {e}[/dim]")
        
        return details
    
    def _scrape_blog_writeups(self, max_reports: int = 20) -> list[RawReport]:
        """Scrape vulnerability write-ups from Bugcrowd resources."""
        reports = []
        
        # Try multiple blog URLs (they change structure often)
        blog_urls = [
            "https://www.bugcrowd.com/blog/",
            "https://www.bugcrowd.com/resources/",
            "https://www.bugcrowd.com/resources/levelup/",
            "https://www.bugcrowd.com/hackers/bugcrowd-university/",
        ]
        
        for blog_url in blog_urls:
            if len(reports) >= max_reports:
                break
                
            try:
                response = self._fetch_with_retry(blog_url)
                if not response or response.status_code != 200:
                    continue
                
                soup = BeautifulSoup(response.text, "html.parser")
                
                # Find all article links
                articles = soup.find_all("article")
                if not articles:
                    articles = soup.find_all("div", class_=re.compile(r"post|article|card", re.I))
                if not articles:
                    articles = soup.find_all("a", href=re.compile(r"/blog/|/resources/"))
                
                for article in articles[:max_reports]:
                    if len(reports) >= max_reports:
                        break
                    
                    try:
                        link = article.find("a", href=True) if article.name != "a" else article
                        if not link:
                            continue
                        
                        url = link.get("href", "")
                        if not url:
                            continue
                        
                        # Make absolute URL
                        if url.startswith("/"):
                            url = f"{self.BASE_URL}{url}"
                        elif not url.startswith("http"):
                            continue
                        
                        # Skip non-blog URLs
                        if "/blog/" not in url and "/resources/" not in url:
                            continue
                        
                        report_id = self._generate_id(url)
                        if self._report_exists(report_id):
                            continue
                        
                        # Get title
                        title_elem = article.find("h2") or article.find("h3") or article.find("h4") or link
                        title = title_elem.get_text(strip=True) if title_elem else "Unknown"
                        
                        # Fetch article body
                        article_response = self._fetch_with_retry(url)
                        body = None
                        if article_response and article_response.status_code == 200:
                            article_soup = BeautifulSoup(article_response.text, "html.parser")
                            content = article_soup.find("article") or article_soup.find("main") or article_soup.find("div", class_=re.compile(r"content|post-body", re.I))
                            if content:
                                body = content.get_text(separator="\n", strip=True)
                        
                        if not body or len(body) < 100:
                            continue
                        
                        # Detect vulnerability type from title/body
                        vuln_type = self._detect_vuln_type(title + " " + body)
                        
                        report = RawReport(
                            id=report_id,
                            source=self.SOURCE_NAME,
                            title=title,
                            url=url,
                            body=body,
                            vuln_type=vuln_type,
                            severity="medium",
                        )
                        
                        self._save_report(report)
                        reports.append(report)
                        
                    except Exception as e:
                        continue
                        
            except Exception as e:
                console.print(f"[dim]Error scraping {blog_url}: {e}[/dim]")
                continue
        
        return reports
    
    def _detect_vuln_type(self, text: str) -> Optional[str]:
        """Detect vulnerability type from text content."""
        text_lower = text.lower()
        
        vuln_patterns = [
            (r"idor|insecure direct object", "IDOR"),
            (r"sql.?injection|sqli", "SQL Injection"),
            (r"xss|cross.?site.?script", "XSS"),
            (r"ssrf|server.?side.?request", "SSRF"),
            (r"csrf|cross.?site.?request.?forgery", "CSRF"),
            (r"auth.?bypass|authentication.?bypass", "Authentication Bypass"),
            (r"broken.?access|access.?control", "Broken Access Control"),
            (r"race.?condition", "Race Condition"),
            (r"rce|remote.?code.?execution", "RCE"),
            (r"xxe|xml.?external", "XXE"),
            (r"path.?traversal|directory.?traversal", "Path Traversal"),
            (r"business.?logic", "Business Logic"),
            (r"information.?disclosure|info.?leak", "Information Disclosure"),
            (r"privilege.?escalation", "Privilege Escalation"),
            (r"open.?redirect", "Open Redirect"),
        ]
        
        for pattern, vuln_type in vuln_patterns:
            if re.search(pattern, text_lower):
                return vuln_type
        
        return None
    
    def scrape(self, max_reports: int = 40, progress: Optional[Progress] = None,
               task: Optional[TaskID] = None) -> list[RawReport]:
        """
        Scrape Bugcrowd disclosed reports.
        
        Args:
            max_reports: Maximum number of reports to scrape
            progress: Rich progress bar
            task: Task ID for progress tracking
            
        Returns:
            List of scraped reports
        """
        reports = []
        page = 1
        max_pages = 10
        
        console.print(f"[cyan]Scraping Bugcrowd disclosures (target: {max_reports} reports)...[/cyan]")
        
        # First try the disclosures page
        while len(reports) < max_reports and page <= max_pages:
            soup = self._fetch_disclosures_page(page)
            if not soup:
                break
            
            # Find disclosure cards
            cards = soup.find_all(class_=re.compile(r"disclosure|card", re.I))
            if not cards:
                cards = soup.find_all("article")
            if not cards:
                cards = soup.find_all("li", class_=re.compile(r"item", re.I))
            
            if not cards:
                break
            
            for card in cards:
                if len(reports) >= max_reports:
                    break
                
                card_data = self._parse_disclosure_card(card)
                if not card_data:
                    continue
                
                if self._report_exists(card_data["id"]):
                    continue
                
                # Fetch full details
                details = self._fetch_disclosure_details(card_data["url"])
                
                report = RawReport(
                    id=card_data["id"],
                    source=self.SOURCE_NAME,
                    title=card_data["title"],
                    url=card_data["url"],
                    severity=card_data["severity"],
                    affected_component=card_data.get("program"),
                    body=details.get("body") if details else None,
                    vuln_type=details.get("vuln_type") if details else None,
                    cwe=details.get("cwe") if details else None,
                    cvss_score=details.get("cvss_score") if details else None,
                )
                
                self._save_report(report)
                reports.append(report)
                
                if progress and task:
                    progress.update(task, advance=1)
            
            page += 1
        
        # Also scrape blog write-ups to supplement
        if len(reports) < max_reports:
            blog_reports = self._scrape_blog_writeups(max_reports - len(reports))
            reports.extend(blog_reports)
            
            if progress and task:
                progress.update(task, advance=len(blog_reports))
        
        console.print(f"[green]Scraped {len(reports)} new Bugcrowd reports[/green]")
        return reports


if __name__ == "__main__":
    from pathlib import Path
    
    data_dir = Path(__file__).parent.parent / "data"
    
    with BugcrowdScraper(data_dir) as scraper:
        reports = scraper.scrape(max_reports=5)
        print(f"Scraped {len(reports)} reports")
        for r in reports[:3]:
            print(f"  - {r.title} ({r.severity})")
