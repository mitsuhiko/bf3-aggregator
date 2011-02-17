$(function() {
  var flashes = $('div.flash');
  if (flashes.length > 0)
    window.setTimeout(function() {
      flashes.animate({'height': 'hide', 'opacity': 'hide'});
    }, 3000);
});
